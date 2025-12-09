require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/oci_client'
require 'logger'

describe LogStash::Outputs::LogAnalytics::Client do
  let(:config_file_location) { ENV["OCI_CONFIG_PATH"] || nil }
  let(:profile_name) { ENV["OCI_PROFILE_NAME"] || nil }
  let(:endpoint) { nil }
  let(:auth_type) { @config_file_location.nil? ? "InstancePrincipal" : "ConfigFile" }
  let(:oci_domain) { nil }
  let(:proxy_ip) { nil }
  let(:proxy_port) { nil }
  let(:proxy_username) { nil }
  let(:proxy_password) { nil }
  @logger = Logger.new(STDOUT)

  describe "Initilize Log Analytics client" do
    it "does not throw error while initializing client" do
      client = described_class.new(@config_file_location, @profile_name, @endpoint, @auth_type,
        @oci_domain, @proxy_ip, @proxy_port, @proxy_username, @proxy_password, @logger)
      expect(client.initialize_loganalytics_client()).not_to raise_error
    end
  end
end