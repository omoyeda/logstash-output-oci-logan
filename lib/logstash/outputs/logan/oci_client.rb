## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require 'oci/auth/auth'
require 'oci/log_analytics/log_analytics'
require 'oci/log_analytics/log_analytics_client'

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

class Client
  @@default_log_level = 'info'
  @@default_log_rotation = 'daily'
  @@validated_log_size = nil
  @@default_log_size = 1 * 1024 * 1024   # 1MB
  @@default_number_of_logs = 10

  def initialize(config_file_location, profile_name, endpoint, auth_type, oci_domain, proxy_ip, proxy_port, proxy_username, proxy_password, logger)
    @@logger = logger
    @config_file_location = config_file_location
    @profile_name = profile_name
    @endpoint = endpoint
    @auth_type = auth_type
    @oci_domain = oci_domain
    @proxy_ip = proxy_ip
    @proxy_port = proxy_port
    @proxy_username = proxy_username
    @proxy_password = proxy_password

    @loganalytics_client = nil
  end

  attr_reader :loganalytics_client

  # This function authenticates to a client so it can later be used to send Logs to OCI.
  def initialize_loganalytics_client()
    if is_valid(@config_file_location)
        @auth_type = "ConfigFile"
    end

    case @auth_type
    when "InstancePrincipal"
      instance_principals_signer = nil
      la_endpoint = nil
      if is_valid(@oci_domain)
        fedration_endpoint = "https://auth.#{@oci_domain}/v1/x509"
        instance_principals_signer = OCI::Auth::Signers::InstancePrincipalsSecurityTokenSigner.new(
          federation_endpoint: fedration_endpoint)
        @@logger.info "Custom Federation Endpoint: #{fedration_endpoint}"
      else
        instance_principals_signer = OCI::Auth::Signers::InstancePrincipalsSecurityTokenSigner.new
      end
      if is_valid(@endpoint)
        la_endpoint = @endpoint
        @@logger.info "Initializing loganalytics_client with endpoint: #{la_endpoint}"
      elsif is_valid(@oci_domain)
        la_endpoint = "https://loganalytics.#{@oci_domain}"
        @@logger.info "Initializing loganalytics_client with custom domain endpoint: #{la_endpoint}"
      end
      @loganalytics_client = OCI::LogAnalytics::LogAnalyticsClient.new(
        config: OCI::Config.new,
        endpoint: la_endpoint,
        signer: instance_principals_signer)
      @@logger.info 'loganalytics_client initialized.'
    when "WorkloadIdentity"
      la_endpoint = nil
      workload_identity_signer = OCI::Auth::Signers::oke_workload_resource_principal_signer
      if is_valid(@endpoint)
        la_endpoint = @endpoint
        @@logger.info "Initializing loganalytics_client with endpoint: #{@endpoint}"
      elsif is_valid(@oci_domain)
        la_endpoint = "https://loganalytics.#{@oci_domain}"
        @@logger.info "Initializing loganalytics_client with custom domain endpoint: #{la_endpoint}"
      end
      @loganalytics_client = OCI::LogAnalytics::LogAnalyticsClient.new(
        config: OCI::Config.new,
        endpoint: la_endpoint,
        signer: workload_identity_signer)
      @@logger.info 'loganalytics_client initialized.'
    when "ConfigFile"
      my_config = OCI::ConfigFileLoader.load_config(
        config_file_location: @config_file_location,
        profile_name: @profile_name)
      no_retry = OCI::Retry::RetryConfig.new(
        max_attempts: 1, # Total attempts including the initial call
        # Other parameters are effectively ignored when max_attempts is 1, 
        # but you still need to provide default or valid values if they are mandatory 
        # in the specific Ruby SDK version's initializer signature:
        base_sleep_time_millis: 1, 
        exponential_growth_factor: 1, 
        should_retry_exception_proc: proc { |exception| false }, # Always return false for any exception
        sleep_calc_millis_proc: proc { |attempt_number, base_sleep_time_millis, max_sleep_between_attempts_millis| 0 }
      )
      example_retry_config = OCI::Retry::RetryConfig.new(
        base_sleep_time_millis: 1,
        exponential_growth_factor: 1,
        should_retry_exception_proc: OCI::Retry::Functions::ShouldRetryOnError.retry_on_network_error_throttle_and_internal_server_errors, # rubocop:disable Metrics/LineLength
        sleep_calc_millis_proc: OCI::Retry::Functions::Sleep.exponential_backoff_with_full_jitter,
        max_attempts: 1,
        # max_elapsed_time_millis: 300_000, # 5 minutes
        # max_sleep_between_attempts_millis: 10_000
      )
      la_endpoint = nil
      if is_valid(@endpoint)
        la_endpoint = @endpoint
        @@logger.info "Initializing loganalytics_client with endpoint: #{la_endpoint}"
      elsif is_valid(@oci_domain)
        la_endpoint = "https://loganalytics.#{@oci_domain}"
        @@logger.info "Initializing loganalytics_client with custom domain endpoint: #{la_endpoint}"
      end
      # @loganalytics_client = OCI::LogAnalytics::LogAnalyticsClient.new(config: my_config, endpoint: la_endpoint)
      @loganalytics_client = OCI::LogAnalytics::LogAnalyticsClient.new(config: my_config, endpoint: la_endpoint, retry_config: example_retry_config)
      @@logger.info 'loganalytics_client initialized'
    else
      raise LogStash::ConfigurationError, "Invalid authType: #{@auth_type}, valid inputs are -  InstancePrincipal, ConfigFile, WorkloadIdentity"
    end

    if is_valid(@proxy_ip) && is_number(@proxy_port)
        if is_valid(@proxy_username)  && is_valid(@proxy_password)
          @loganalytics_client.api_client.proxy_settings = OCI::ApiClientProxySettings.new(@proxy_ip, @proxy_port, @proxy_username, @proxy_password)
        else
          @loganalytics_client.api_client.proxy_settings = OCI::ApiClientProxySettings.new(@proxy_ip, @proxy_port)
        end
    end

    rescue => ex
      @@logger.error {"Error occurred while initializing LogAnalytics Client:
                          authType: #{@auth_type},
                          errorMessage: #{ex}"}
  end

  def is_valid(field)
    if field.nil? || field.empty? then
      return false
    else
      return true
    end
  end

  def is_number(field)
    true if Integer(field) rescue false
  end
end