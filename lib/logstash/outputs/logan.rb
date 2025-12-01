# encoding: utf-8
require "logstash/outputs/base"

# require 'zip'
# require 'yajl'
# require 'yajl/json_gem'
require 'logger'

require_relative 'logan/log_grouper'
require_relative 'logan/oci_client'
require_relative 'logan/oci_uploader'

# require_relative '../metrics/prometheusMetrics'
require_relative '../enums/source'

# Import only specific OCI modules to improve load times and reduce the memory requirements.
# require 'oci/auth/auth'
# require 'oci/log_analytics/log_analytics'
# require 'oci/log_analytics/log_analytics_client'

# Workaround until OCI SDK releases a proper fix to load only specific service related modules/client.
# require 'oci/api_client'
# require 'oci/api_client_proxy_settings'
# require 'oci/config'
# require 'oci/config_file_loader'
# require 'oci/errors'
# require 'oci/global_context'
# require 'oci/internal/internal'
# require 'oci/regions'
# require 'oci/regions_definitions'
# require 'oci/response_headers'
# require 'oci/response'
# require 'oci/base_signer'
# require 'oci/signer'
# require 'oci/version'
# require 'oci/waiter'
# require 'oci/retry/retry'
# require 'oci/object_storage/object_storage'

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
  config_name "logan"
  concurrency :single
  default :codec, "line"

  MAX_PAYLOAD_SIZE_BYTES = 2 * 1080 * 1080 # 2 MB

  @@logger = nil
  @loganalytics_client = nil
  # @@prometheusMetrics = nil
  @@logger_config_errors = []
  # @@worker_id = '0'
  @@encoded_messages_count = 0

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
  # The http proxy to be used
  config :http_proxy, :validate => :string, :default => nil
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
  config :retry_wait_on_4xx, :validate => :number, :default => 2 # seconds
  # The maximum number of times to retry to upload payload while failing
  # if -1 is set, then plugin will retry unlimited times
  config :retry_max_times_on_4xx, :validate => :number, :default => 17

  # Seconds to wait before next retry to flush on 5xx errors
  config :retry_wait_on_5xx, :validate => :number, :default => 2 # seconds
  # The maximum number of times to retry to upload payload while failing
  # if -1 is set, then plugin will retry unlimited times
  config :retry_max_times_on_5xx, :validate => :number, :default => 17

  # The kubernetes_metadata_keys_mapping
  # config :kubernetes_metadata_keys_mapping, :validate => :hash, :default => {"container_name":"Container",
  #         "namespace_name":"Namespace", "pod_name":"Pod","container_image":"Container Image Name","host":"Node"}
  config :collection_source, :validate => :string, :default => Source::LOGSTASH

  # Default function for the plugin - same as initilize method, meant to enforce having super called
  public
  def register
    if is_valid(@oci_domain) && !@oci_domain.match(/\S.oci.\S/)
      raise LogStash::ConfigurationError, "Invalid oci_domain: #{@oci_domain}, valid fmt: <oci-region>.oci.<oci-domain> | ex: us-ashburn-1.oci.oraclecloud.com"
    end
  
    initialize_logger()
    @client = Client.new(@config_file_location, @profile_name, @endpoint, @auth_type, @oci_domain, @proxy_ip, @proxy_port, @proxy_username, @proxy_password, @@logger)

    # @@prometheusMetrics = PrometheusMetrics.instance
    
    @client.initialize_loganalytics_client()
    @loganalytics_client = @client.loganalytics_client

    is_mandatory_fields_valid,invalid_field_name =  mandatory_field_validator
    if !is_mandatory_fields_valid
      @@logger.error {"Error in config file : invalid #{invalid_field_name}"}
      raise LogStash::ConfigurationError, "Error in config file : invalid #{invalid_field_name}"
    end

    # @mutex = Mutex.new
    # @log_grouper = LogGroup.new(@@logger)
    @oci_uploader = Uploader.new(@namespace, @dump_zip_file, @loganalytics_client, @collection_source,
                                 @zip_file_location, @plugin_retry_on_4xx, @plugin_retry_on_5xx, @retry_wait_on_4xx, @retry_max_times_on_4xx,
                                 @retry_wait_on_5xx, @retry_max_times_on_5xx, @@logger)
  end

  # Default function for the plugin
  # This function is resposible for getting the events from Logstash
  # These events need to be written to a local file and be uploaded to OCI
  def multi_receive_encoded(events_encoded)
    log_grouper = LogGroup.new(@@logger)

    chunks = chunk_events(events_encoded)

    chunks.each do |chunk|
      incoming_records_per_tag,invalid_records_per_tag,tag_metrics_set,logGroup_labels_set,
      tags_per_logGroupId,lrpes_for_logGroupId = log_grouper.group_by_logGroupId(chunk)
      
      @oci_uploader.setup_metrics(incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set)
      @oci_uploader.generate_payload(tags_per_logGroupId, lrpes_for_logGroupId)
    end
    # incoming_records_per_tag,invalid_records_per_tag,tag_metrics_set,logGroup_labels_set,
    # tags_per_logGroupId,lrpes_for_logGroupId = log_grouper.group_by_logGroupId(events_encoded)
    
    # @oci_uploader.setup_metrics(incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set)
    # @oci_uploader.generate_payload(tags_per_logGroupId, lrpes_for_logGroupId)
  end

  def chunk_events(events_encoded)
    chunks = []
    current_chunk = []
    current_size = 0

    @@logger.info{"Starting chunking..."}
    events_encoded.each do |event, encoded|
      event_size = event.to_json.bytesize

      # If adding this event would exceed the max size and we already have events in
      # current chunk, start a new chunk
      if current_size + event_size > MAX_PAYLOAD_SIZE_BYTES && !current_chunk.empty?
        @@logger.info{"Chunk is full. Creating a new one."}
        chunks << current_chunk
        current_chunk = []
        current_size = 0
      end
      # Append the event to the chunk
      current_chunk << [event, encoded]
      current_size += event_size
      @@logger.info{"Chunk current size: #{current_size}"}
    end

    # append the last chunk
    chunks << current_chunk unless current_chunk.empty?
    return chunks
  end

  # logger
  def initialize_logger()
    begin
      filename = nil
      is_default_log_location = false
      if is_valid(@plugin_log_location)
          filename = @plugin_log_location[-1] == '/' ? @plugin_log_location : @plugin_log_location +'/'
      else
          # @@logger = log
          @@logger = Logger.new(STDOUT)
          return
      end
      if !is_valid_log_level(@plugin_log_level)
          @plugin_log_level = @@default_log_level
      end
      oci_logstash_output_plugin_log = nil
      if is_default_log_location
          oci_logstash_output_plugin_log = 'oci-logging-analytics.log'
      else
          oci_logstash_output_plugin_log = filename+'oci-logging-analytics.log'
      end
      logger_config = nil

      if is_valid_number_of_logs(@plugin_log_file_count) && is_valid_log_size(@plugin_log_file_size)
          # When customer provided valid log_file_count and log_file_size.
          # logger will rotate with max log_file_count with each file having max log_file_size.
          # Older logs purged automatically.
          @@logger = Logger.new(oci_logstash_output_plugin_log, @plugin_log_file_count, @@validated_log_size)
          logger_config = 'USER_CONFIG'
      elsif is_valid_log_rotation(@plugin_log_rotation)
          # When customer provided only log_rotation.
          # logger will create a new log based on log_rotation (new file everyday if the rotation is daily).
          # This will create too many logs over a period of time as log purging is not done.
          @@logger = Logger.new(oci_logstash_output_plugin_log, @plugin_log_rotation)
          logger_config = 'FALLBACK_CONFIG'
      else
          # When customer provided invalid log config, default config is considered.
          # logger will rotate with max default log_file_count with each file having max default log_file_size.
          # Older logs purged automatically.
          @@logger = Logger.new(oci_logstash_output_plugin_log, @@default_number_of_logs, @@default_log_size)
          logger_config = 'DEFAULT_CONFIG'
      end

      logger_set_level(@plugin_log_level)
      @@logger.info {"Initializing oci-logging-analytics plugin"}
      if is_default_log_location
          @@logger.info {"plugin_log_location is not specified. oci-logging-analytics.log will be generated under directory from where logstash is executed."}
      end

      case logger_config
          when 'USER_CONFIG'
          @@logger.info {"Logger for oci-logging-analytics.log is initialized with config values log size: #{@plugin_log_file_size}, number of logs: #{@plugin_log_file_count}"}
          when 'FALLBACK_CONFIG'
          @@logger.info {"Logger for oci-logging-analytics.log is initialized with log rotation: #{@plugin_log_rotation}"}
          when 'DEFAULT_CONFIG'
          @@logger.info {"Logger for oci-logging-analytics.log is initialized with default config values log size: #{@@default_log_size}, number of logs: #{@@default_number_of_logs}"}
      end
      if @@logger_config_errors.length > 0
          @@logger_config_errors. each {|logger_config_error|
          @@logger.warn {"#{logger_config_error}"}
          }
      end
    rescue => ex
      # @@logger = log
      @@logger = Logger.new(STDOUT)
      @@logger.error {"Error while initializing logger:#{ex.inspect}"}
      @@logger.info {"Redirecting oci log analytics logs to STDOUT"}
    end
  end

  def is_valid(field)
    if field.nil? || field.empty? then
      return false
    else
      return true
    end
  end

  def is_valid_log_rotation(log_rotation)
    if !is_valid(log_rotation)
      return false
    end
    case log_rotation.downcase
        when "daily"
          return true
        when "weekly"
          return true
        when "monthly"
          return true
        else
          @@logger_config_error << "Only 'daily'/'weekly'/'monthly' are supported for 'plugin_log_rotation'."
          return false
      end
  end

  def is_valid_log_level(param)
    if !is_valid(param)
      return false
    end
    case param.upcase
      when "DEBUG"
        return true
      when "INFO"
        return true
      when "WARN"
        return true
      when "ERROR"
        return true
      when "FATAL"
        return true
      when "UNKNOWN"
        return true
      else
        return false
    end
  end

  def logger_set_level(param)
    # DEBUG < INFO < WARN < ERROR < FATAL < UNKNOWN
    case @plugin_log_level.upcase
      when "DEBUG"
        @@logger.level = Logger::DEBUG
      when "INFO"
        @@logger.level = Logger::INFO
      when "WARN"
        @@logger.level = Logger::WARN
      when "ERROR"
        @@logger.level = Logger::ERROR
      when "FATAL"
        @@logger.level = Logger::FATAL
      when "UNKNOWN"
        @@logger.level = Logger::UNKNOWN
    end
  end

  def is_number(field)
    true if Integer(field) rescue false
  end

  def is_valid_log_size(log_size)
    if log_size != nil
      case log_size.to_s
        when /([0-9]+)k/i
          log_size = $~[1].to_i * 1024
        when /([0-9]+)m/i
          log_size = $~[1].to_i * (1024 ** 2)
        when /([0-9]+)g/i
          log_size = $~[1].to_i * (1024 ** 3)
        else
          @@logger_config_errors << "plugin_log_file_size must be greater than 1KB."
          return false
      end
      @@validated_log_size = log_size
      return true
    else
      return false
    end
  end

  def is_valid_number_of_logs(number_of_logs)
    if !is_number(number_of_logs) || number_of_logs < 1
      @@logger_config_errors << "plugin_log_file_count must be greater than zero"
      return false
    end
    return true
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
end # class LogStash::Outputs::Logan
