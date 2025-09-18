# encoding: utf-8
require "logstash/outputs/base"

require 'logger'

# Workaround until OCI SDK releases a proper fix to load only specific service related modules/client.
require 'oci/api_client'
require 'oci/api_client_proxy_settings'
require 'oci/config'
require 'oci/config_file_loader'
require 'oci/errors'
require 'oci/global_context'
require 'oci/internal/internal'
require 'oci/regions'
require 'oci/regions_definitions'
require 'oci/response_headers'
require 'oci/response'
require 'oci/base_signer'
require 'oci/signer'
require 'oci/version'
require 'oci/waiter'
require 'oci/retry/retry'
require 'oci/object_storage/object_storage'

# An logan output that does nothing.
class LogStash::Outputs::Logan < LogStash::Outputs::Base
  config_name "logan"

  concurrency :single

  # class variables used by fluentd project, still figuring out what they do
  @@logger = nil
  @@loganalytics_client = nil
  @@prometheusMetrics = nil
  @@logger_config_errors = []
  @@worker_id = '0'
  @@encoded_messages_count = 0

  # ---------------------------------------------------------------
  # Parameters
  # ---------------------------------------------------------------

  # Sets the mandatory OCI Tenancy Namespace to which the collected log data will be uploaded
  config :namespace, :validate => :string, :default => nil #, :required => true
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

  # ---------------------------------------------------------------
  # Proxy parameters. Used for client
  # ---------------------------------------------------------------
  #****************************************************************
    # The http proxy to be used
    config :http_proxy, :validate => :string, :default => nil
    # The proxy_ip to be used
    config :proxy_ip, :validate => :string, :default => nil
    # The proxy_port to be used
    config :proxy_port, :validate => :integer, :default => 80
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
    config :plugin_log_file_count, :validate => :integer, :default => 10

  # Default function for the plugin - same as initilize method, meant to enforce having super called
  public
  def register
    super
    initialize_logger()
    initialize_loganalytics_client()
  end # def register

  # Default function for the plugin
  # This function is resposible for getting the events from Logstash
  # These events need to be written to a local file and be uploaded to OCI

  def multi_receive_encoded(events_encoded)
    events_encoded.each do |event, data|
      # write_to_zip(data)
      $stdout.write(event)
    end
  end
end # class LogStash::Outputs::Logan
