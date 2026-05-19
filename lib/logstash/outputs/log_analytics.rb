# frozen_string_literal: true

require 'logstash/outputs/base'
require 'logstash/namespace'
require 'logger'

# require_relative 'logan/log_grouper'
require_relative '../enums/source'

# OCI SDK configuration hooks used by the plugin.
module OCI
  class << self
    attr_accessor :sdk_name

    # Defines the logger used for debugging for the OCI module.
    # For example, log to STDOUT by setting this to Logger.new(STDOUT).
    #
    # @return [Logger]
    attr_accessor :logger
  end
end

# Logstash output plugin for uploading records to OCI Log Analytics.
# rubocop:disable Style/ClassAndModuleChildren, Metrics/ClassLength
class LogStash::Outputs::Logan < LogStash::Outputs::Base
  require 'logstash/outputs/logan/oci_client'
  require 'logstash/outputs/logan/oci_uploader'
  require 'logstash/outputs/logan/log_grouper'

  VALID_AUTH_TYPES = %w[InstancePrincipal ConfigFile].freeze
  VALID_LOG_LEVELS = %w[DEBUG INFO WARN ERROR FATAL UNKNOWN].freeze

  attr_reader :oci_uploader, :oci_client

  config_name 'log_analytics'
  concurrency :shared
  default :codec, 'line'

  # ---------------------------------------------------------------
  # Parameters
  # ---------------------------------------------------------------

  # Sets the mandatory OCI Tenancy Namespace to which the collected log data will be uploaded
  config :namespace, validate: :string, default: nil, required: true
  # OCI config file location. Used for session
  config :config_file_location, validate: :string, default: nil
  # Name of the profile to be used
  config :profile_name, validate: :string, default: 'DEFAULT'
  # OCI endpoint
  config :endpoint, validate: :string, default: nil
  # AuthType to be used
  config :auth_type, validate: :string, default: 'InstancePrincipal'
  # OCI Domain
  config :oci_domain, validate: :string, default: nil
  # Enable local payload dump
  config :dump_zip_file, validate: :boolean, default: false
  # Payload zip File Location
  config :zip_file_location, validate: :string, default: nil

  # ---------------------------------------------------------------
  # Proxy parameters. Used for client
  # ---------------------------------------------------------------
  # ****************************************************************
  # The proxy_ip to be used
  config :proxy_ip, validate: :string, default: nil
  # The proxy_port to be used
  config :proxy_port, validate: :number, default: 80
  # The proxy_username to be used
  config :proxy_username, validate: :string, default: nil
  # The proxy_password to be used
  config :proxy_password, validate: :string, default: nil

  # OCI Output plugin log location
  config :plugin_log_location, validate: :string, default: nil
  # OCI Output plugin log level
  config :plugin_log_level, validate: :string, default: nil
  # OCI Output plugin log rotation
  config :plugin_log_rotation, validate: :string, default: nil
  # The maximum log file size at which point the log file to be rotated
  config :plugin_log_file_size, validate: :string, default: nil
  # The number of archived/rotated log files to keep
  config :plugin_log_file_count, validate: :number, default: 10

  # OCI Output plugin 4xx exception handling - Except '429'
  config :plugin_retry_on_4xx, validate: :boolean, default: false

  # OCI Output plugin 5xx exception handling
  config :plugin_retry_on_5xx, validate: :boolean, default: false

  # ---------------------------------------------------------------
  # Retry parameters
  # ---------------------------------------------------------------
  # Seconds to wait before next retry to flush on 4xx errors
  config :retry_wait_on_4xx, validate: :number, default: 3 # seconds
  # The maximum number of times to retry to upload payload while failing
  # if -1 is set, then plugin will retry unlimited times
  config :retry_max_times_on_4xx, validate: :number, default: 17

  # Seconds to wait before next retry to flush on 5xx errors
  config :retry_wait_on_5xx, validate: :number, default: 3 # seconds
  # The maximum number of times to retry to upload payload while failing
  # if -1 is set, then plugin will retry unlimited times
  config :retry_max_times_on_5xx, validate: :number, default: 17
  config :collection_source, validate: :string, default: Source::LOGSTASH

  # Default function for the plugin - same as initilize method, meant to enforce having super called
  # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
  def register
    if is_valid(@oci_domain) && !@oci_domain.match(/\S.oci.\S/)
      raise LogStash::ConfigurationError,
            [
              "Invalid oci_domain: #{@oci_domain}, valid fmt: ",
              '<oci-region>.oci.<oci-domain> | ex: ',
              'us-ashburn-1.oci.oraclecloud.com'
            ].join
    end
    if @dump_zip_file && !valid_directory_path?(@zip_file_location)
      raise LogStash::ConfigurationError,
            [
              "Invalid zip_file_location: #{@zip_file_location}, ",
              'zip_file_location must be an existing writable directory ',
              'when enabling dump_zip_file.'
            ].join
    end

    initialize_logger
    validate_auth_type!

    is_mandatory_fields_valid, invalid_field_name = mandatory_field_validator
    unless is_mandatory_fields_valid
      @plugin_logger.error("Error in config file : invalid #{invalid_field_name}")
      raise LogStash::ConfigurationError, "Error in config file : invalid #{invalid_field_name}"
    end

    client_for_current_thread

    @oci_uploader = LogStash::Outputs::LogAnalytics::Uploader.new(
      @namespace,
      @dump_zip_file,
      method(:client_for_current_thread),
      @collection_source,
      @zip_file_location,
      @plugin_retry_on_4xx,
      @plugin_retry_on_5xx,
      @retry_wait_on_4xx,
      @retry_max_times_on_4xx,
      @retry_wait_on_5xx,
      @retry_max_times_on_5xx,
      @plugin_logger
    )
    @log_grouper = LogStash::Outputs::LogAnalytics::LogGroup.new(@plugin_logger)
  end
  # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

  # Default function for the plugin
  # This function is resposible for getting the events from Logstash
  # These events need to be written to a local file and be uploaded to OCI
  def multi_receive_encoded(events_encoded)
    incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set, _,
    tags_per_log_group_id, lrpes_for_log_group_id = @log_grouper.group_by_logGroupId(events_encoded)

    @oci_uploader.show_dropped_messages(incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set)
    @oci_uploader.generate_payload(tags_per_log_group_id, lrpes_for_log_group_id)
  end

  def do_close
    clear_cached_clients
    super if defined?(super)
  end

  # logger
  # rubocop:disable Metrics/MethodLength
  def initialize_logger
    $stdout.sync = true if $stdout.respond_to?(:sync=)
    @plugin_logger = Logger.new($stdout)
    @plugin_logger.level = effective_log_level
    @plugin_logger.formatter = method(:format_log_message)

    if ignored_logger_settings_provided?
      @plugin_logger.warn(
        'plugin_log_location, plugin_log_rotation, plugin_log_file_size, ' \
        'and plugin_log_file_count are ignored; using the plugin STDOUT ' \
        'logger instead.'
      )
    end

    return unless is_valid(@plugin_log_level) && !valid_log_level?(@plugin_log_level)

    @plugin_logger.warn("Invalid plugin_log_level '#{@plugin_log_level}', defaulting to INFO.")
  end
  # rubocop:enable Metrics/MethodLength

  # rubocop:disable Naming/PredicatePrefix
  def is_valid(field)
    return false if field.nil? || field.empty?

    true
  end

  def valid_directory_path?(path)
    is_valid(path) && ::File.directory?(path) && ::File.writable?(path)
  end

  def is_number(field)
    true if Integer(field)
  rescue StandardError
    false
  end
  # rubocop:enable Naming/PredicatePrefix

  def mandatory_field_validator
    if !is_valid(@namespace)
      [false, 'namespace']
    elsif !is_valid(@config_file_location) && @auth_type == 'ConfigFile'
      [false, 'config_file_location']
    elsif !is_valid(@profile_name) && @auth_type == 'ConfigFile'
      [false, 'profile_name']
    else
      [true, nil]
    end
  end

  private

  def effective_auth_type
    is_valid(@config_file_location) ? 'ConfigFile' : @auth_type
  end

  def validate_auth_type!
    return if VALID_AUTH_TYPES.include?(effective_auth_type)

    raise LogStash::ConfigurationError,
          "Invalid authType: #{@auth_type}, valid inputs are -  InstancePrincipal, ConfigFile"
  end

  def client_for_current_thread
    cached_client = Thread.current.thread_variable_get(thread_client_key)
    return cached_client if cached_client

    client = build_loganalytics_client
    register_client_thread(Thread.current)
    Thread.current.thread_variable_set(thread_client_key, client)
  end

  # rubocop:disable Metrics/MethodLength
  def build_loganalytics_client
    client_wrapper = LogStash::Outputs::LogAnalytics::Client.new(
      @config_file_location,
      @profile_name,
      @endpoint,
      effective_auth_type,
      @oci_domain,
      @proxy_ip,
      @proxy_port,
      @proxy_username,
      @proxy_password,
      @plugin_logger
    )
    client_wrapper.initialize_loganalytics_client
    client_wrapper.loganalytics_client
  end
  # rubocop:enable Metrics/MethodLength

  def thread_client_key
    @thread_client_key ||= :"logan_oci_client_#{object_id}"
  end

  def register_client_thread(thread)
    client_threads_mutex.synchronize do
      @client_threads ||= []
      @client_threads << thread unless @client_threads.include?(thread)
    end
  end

  def clear_cached_clients
    client_threads_mutex.synchronize do
      Array(@client_threads).each do |thread|
        thread.thread_variable_set(thread_client_key, nil)
      rescue ThreadError
        next
      end
      @client_threads = []
    end
  end

  def client_threads_mutex
    @client_threads_mutex ||= Mutex.new
  end

  def ignored_logger_settings_provided?
    [
      @plugin_log_location,
      @plugin_log_rotation,
      @plugin_log_file_size
    ].any? { |value| is_valid(value) } || @plugin_log_file_count != 10
  end

  def valid_log_level?(level)
    VALID_LOG_LEVELS.include?(level.to_s.upcase)
  end

  def effective_log_level
    return Logger::INFO unless valid_log_level?(@plugin_log_level)

    Logger.const_get(@plugin_log_level.upcase)
  end

  def format_log_message(severity, datetime, progname, message)
    formatted_time = datetime.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    thread_label = "thread-#{Thread.current.object_id}"
    progname_segment = progname ? " #{progname}" : ''

    "#{formatted_time} #{severity} [#{thread_label}]#{progname_segment}: #{String(message)}\n"
  end
end
# rubocop:enable Style/ClassAndModuleChildren, Metrics/ClassLength
