require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/oci_client'
require 'logger'

describe LogStash::Outputs::LogAnalytics::Client do
  config_file_location = ENV["OCI_CONFIG_PATH"] || nil
  profile_name = ENV["OCI_PROFILE_NAME"] || nil
  endpoint = nil
  auth_type = config_file_location.nil? ? "InstancePrincipal" : "ConfigFile"
  oci_domain = nil
  proxy_ip = nil
  proxy_port = nil
  proxy_username = nil
  proxy_password = nil
  logger = Logger.new(STDOUT)

  describe "Initialize Log Analytics client" do
    it "does not fail while initializing Log Analytics Client" do
      client = described_class.new(config_file_location, profile_name, endpoint, auth_type,
        oci_domain, proxy_ip, proxy_port, proxy_username, proxy_password, logger)
      expect { client.initialize_loganalytics_client() }.not_to raise_error
      expect(client.loganalytics_client).to be_an_instance_of(OCI::LogAnalytics::LogAnalyticsClient)
    end
  end
end