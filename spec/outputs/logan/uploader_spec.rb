require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/oci_uploader'
require 'logger'

describe LogStash::Outputs::LogAnalytics::Uploader do
  namespace = ENV["OCI_NAMESPACE"] || nil
  dump_zip_file = true
  loganalytics_client = nil
  collection_source = nil
  zip_file_location = "/tmp/"
  plugin_retry_on_4xx = nil
  plugin_retry_on_5xx = nil
  retry_wait_on_4xx = nil
  retry_max_times_on_4xx = nil
  retry_wait_on_5xx = nil
  retry_max_times_on_5xx = nil
  logger = Logger.new(STDOUT)

  describe "Initialize Uploader" do
    it "does not fail while generating payload with sample logs" do
      uploader = described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
        zip_file_location, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx, retry_wait_on_5xx, retry_max_times_on_5xx, logger)
      expect { uploader.generate_payload() }.not_to raise_error
    end
  end
end