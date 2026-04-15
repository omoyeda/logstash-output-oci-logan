require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/oci_client'
require 'logger'

describe LogStash::Outputs::LogAnalytics::Client do
  # client with config file
  config_file_location = ENV["OCI_CONFIG_PATH"] || nil
  profile_name = ENV["OCI_PROFILE_NAME"] || "DEFAULT"
  endpoint = nil
  auth_type = config_file_location.nil? ? "InstancePrincipal" : "ConfigFile"
  oci_domain = nil
  proxy_ip = nil
  proxy_port = nil
  proxy_username = nil
  proxy_password = nil
  logger = Logger.new(STDOUT)

  proxy_ip = ENV["PROXY_IP"]
  proxy_port = ENV["PROXY_PORT"]
  proxy_username = nil
  proxy_password = nil

  describe "#initialize_loganalytics_client" do
    test_with_configfile = false
    if auth_type == "ConfigFile"
      test_with_configfile = true
    end
    context "with ConfigFile", if: test_with_configfile do
      it "initializes a Log Analytics Client", :integration_test do
        client = described_class.new(config_file_location, profile_name, endpoint, auth_type,
          oci_domain, proxy_ip, proxy_port, proxy_username, proxy_password, logger)
        expect { client.initialize_loganalytics_client() }.not_to raise_error
        expect(client.loganalytics_client).to be_an_instance_of(OCI::LogAnalytics::LogAnalyticsClient)
      end
      
      it "initializes using basic proxy configuration", :integration_test do
        client = described_class.new(config_file_location, profile_name, endpoint, auth_type,
          oci_domain, proxy_ip, proxy_port, proxy_username, proxy_password, logger)
        expect { client.initialize_loganalytics_client() }.not_to raise_error
        expect(client.loganalytics_client).to be_an_instance_of(OCI::LogAnalytics::LogAnalyticsClient)
      end
    end

    context "with InstancePrincipal", if: !test_with_configfile do
      it "returns an InstancePrincipal authenticated client", :integration_test do
        client = described_class.new(nil, nil, nil, "InstancePrincipal",
          nil, nil, nil, nil, nil, logger)
        expect { client.initialize_loganalytics_client() }.not_to raise_error
        expect(client.loganalytics_client).to be_an_instance_of(OCI::LogAnalytics::LogAnalyticsClient)
      end
    end
  end
end