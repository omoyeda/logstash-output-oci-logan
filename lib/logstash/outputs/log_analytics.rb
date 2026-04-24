# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"

# require_relative 'logan/log_grouper'
require_relative '../enums/source'

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

class LogStash::Outputs::Logan < LogStash::Outputs::Base
  require 'logstash/outputs/logan/oci_client'
  require 'logstash/outputs/logan/oci_uploader'
  require 'logstash/outputs/logan/log_grouper'

  VALID_AUTH_TYPES = %w[InstancePrincipal ConfigFile].freeze

  attr_reader :oci_uploader
  attr_reader :oci_client

  config_name "log_analytics"
  concurrency :shared
  default :codec, "line"

  # ---------------------------------------------------------------
  # Parameters
  # ---------------------------------------------------------------

  # Sets the mandatory OCI Tenancy Namespace to which the collected log data will be uploaded
  config :namespace, :validate => :string, :default => nil, :required => true
  # OCI config file location. Used for session
  config :config_file_location, :validate => :string, :default => nil
  # Name of the profile to be used
  config :profile_name, :validate => :string, :default => 'DEFAULT'
  # OCI endpoint
  config :endpoint, :validate => :string, :default => nil
  # AuthType to be used
  config :auth_type, :validate => :string, :default => 'InstancePrincipal'
  # OCI Domain
  config :oci_domain, :validate => :string, :default => nil
  # Enable local payload dump
  config :dump_zip_file, :validate => :boolean, :default => false
  # Payload zip File Location
  config :zip_file_location, :validate => :string, :default => nil

  # ---------------------------------------------------------------
  # Proxy parameters. Used for client
  # ---------------------------------------------------------------
  #****************************************************************
  # The proxy_ip to be used
  config :proxy_ip, :validate => :string, :default => nil
  # The proxy_port to be used
  config :proxy_port, :validate => :number, :default => 80
  # The proxy_username to be used
  config :proxy_username, :validate => :string, :default => nil
  # The proxy_password to be used
  config :proxy_password, :validate => :string, :default => nil

  # OCI Output plugin log location
  config :plugin_log_location, :validate => :string, :default => nil
  # OCI Output plugin log level
  config :plugin_log_level, :validate => :string, :default => nil
  # OCI Output plugin log rotation
  config :plugin_log_rotation, :validate => :string, :default => nil
  # The maximum log file size at which point the log file to be rotated
  config :plugin_log_file_size, :validate => :string, :default => nil
  # The number of archived/rotated log files to keep
  config :plugin_log_file_count, :validate => :number, :default => 10

  # OCI Output plugin 4xx exception handling - Except '429'
  config :plugin_retry_on_4xx, :validate => :boolean, :default => false

  # OCI Output plugin 5xx exception handling
  config :plugin_retry_on_5xx, :validate => :boolean, :default => false

  
  # ---------------------------------------------------------------
  # Retry parameters
  # ---------------------------------------------------------------
  # Seconds to wait before next retry to flush on 4xx errors
  config :retry_wait_on_4xx, :validate => :number, :default => 3 # seconds
  # The maximum number of times to retry to upload payload while failing
  # if -1 is set, then plugin will retry unlimited times
  config :retry_max_times_on_4xx, :validate => :number, :default => 17

  # Seconds to wait before next retry to flush on 5xx errors
  config :retry_wait_on_5xx, :validate => :number, :default => 3 # seconds
  # The maximum number of times to retry to upload payload while failing
  # if -1 is set, then plugin will retry unlimited times
  config :retry_max_times_on_5xx, :validate => :number, :default => 17
  config :collection_source, :validate => :string, :default => Source::LOGSTASH

  # Default function for the plugin - same as initilize method, meant to enforce having super called
  public
  def register
    if is_valid(@oci_domain) && !@oci_domain.match(/\S.oci.\S/)
      raise LogStash::ConfigurationError, "Invalid oci_domain: #{@oci_domain}, valid fmt: <oci-region>.oci.<oci-domain> | ex: us-ashburn-1.oci.oraclecloud.com"
    end
    if @dump_zip_file && !valid_directory_path?(@zip_file_location)
      raise LogStash::ConfigurationError, "Invalid zip_file_location: #{@zip_file_location}, zip_file_location must be an existing writable directory when enabling dump_zip_file."
    end
  
    initialize_logger()
    validate_auth_type!

    is_mandatory_fields_valid,invalid_field_name =  mandatory_field_validator
    if !is_mandatory_fields_valid
      @logger.error("Error in config file : invalid #{invalid_field_name}")
      raise LogStash::ConfigurationError, "Error in config file : invalid #{invalid_field_name}"
    end

    client_for_current_thread

    @oci_uploader = LogStash::Outputs::LogAnalytics::Uploader.new(@namespace, @dump_zip_file, method(:client_for_current_thread), @collection_source,
                                 @zip_file_location, @plugin_retry_on_4xx, @plugin_retry_on_5xx, @retry_wait_on_4xx, @retry_max_times_on_4xx,
                                 @retry_wait_on_5xx, @retry_max_times_on_5xx, @logger)
    @log_grouper = LogStash::Outputs::LogAnalytics::LogGroup.new(@logger)
  end

  # Default function for the plugin
  # This function is resposible for getting the events from Logstash
  # These events need to be written to a local file and be uploaded to OCI
  def multi_receive_encoded(events_encoded)
    incoming_records_per_tag,invalid_records_per_tag,tag_metrics_set,logGroup_labels_set,
    tags_per_logGroupId,lrpes_for_logGroupId = @log_grouper.group_by_logGroupId(events_encoded)
    
    @oci_uploader.show_dropped_messages(incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set)
    @oci_uploader.generate_payload(tags_per_logGroupId, lrpes_for_logGroupId)
  end

  # logger
  def initialize_logger()
    if logger_settings_provided?
      @logger.warn("plugin_log_location, plugin_log_level, plugin_log_rotation, plugin_log_file_size, and plugin_log_file_count are ignored; using the Logstash plugin logger instead.")
    end
  end

  def is_valid(field)
    if field.nil? || field.empty? then
      return false
    else
      return true
    end
  end

  def valid_directory_path?(path)
    is_valid(path) && ::File.directory?(path) && ::File.writable?(path)
  end

  def is_number(field)
    true if Integer(field) rescue false
  end

  def mandatory_field_validator
    begin
      if !is_valid(@namespace)
        return false,'namespace'
      elsif !is_valid(@config_file_location) && @auth_type == 'ConfigFile'
        return false,'config_file_location'
      elsif !is_valid(@profile_name)  && @auth_type == 'ConfigFile'
        return false,'profile_name'
      else
        return true,nil
      end
    end
  end

  private

  def effective_auth_type
    is_valid(@config_file_location) ? 'ConfigFile' : @auth_type
  end

  def validate_auth_type!
    return if VALID_AUTH_TYPES.include?(effective_auth_type)

    raise LogStash::ConfigurationError, "Invalid authType: #{@auth_type}, valid inputs are -  InstancePrincipal, ConfigFile"
  end

  def client_for_current_thread
    Thread.current[thread_client_key] ||= build_loganalytics_client
  end

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
      @logger
    )
    client_wrapper.initialize_loganalytics_client()
    client_wrapper.loganalytics_client
  end

  def thread_client_key
    @thread_client_key ||= :"logan_oci_client_#{object_id}"
  end

  def logger_settings_provided?
    [
      @plugin_log_location,
      @plugin_log_level,
      @plugin_log_rotation,
      @plugin_log_file_size
    ].any? { |value| is_valid(value) } || @plugin_log_file_count != 10
  end
end # class LogStash::Outputs::Logan
