require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/oci_uploader'
require "logstash/event"
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
  retry_wait_on_5xx = 1
  retry_max_times_on_5xx = nil

  let(:log_output) { StringIO.new }
  let(:logger) { Logger.new(log_output) }

  subject { described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
        zip_file_location, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx,
        retry_wait_on_5xx, retry_max_times_on_5xx, logger) }

  describe "Initialize Uploader" do
    it "does not fail while generating payload with sample logs" do
      uploader = described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
        zip_file_location, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx, retry_wait_on_5xx, retry_max_times_on_5xx, logger)

      event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"]
      })
      tags_per_logGroupId = { ENV["OCI_TEST_LOG_GROUP_ID"] => "" }
      lrpes_for_logGroupId = { ENV["OCI_TEST_LOG_GROUP_ID"] => [[event]] }
      expect { uploader.generate_payload(tags_per_logGroupId, lrpes_for_logGroupId) }.not_to raise_error
    end
  end

  context "testing function return formats" do
    it "get_logSets_map_per_logGroupId returns Hash" do
      event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => nil
      })
      oci_la_log_group_id = ENV["OCI_TEST_LOG_GROUP_ID"]
      records_per_logGroupId = [event]
      
      logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
      expect(logSets_per_logGroupId_map).to be_a(Hash)
      expect(oci_la_global_metadata).to be_nil
    end

    # it "get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map) returns zip" do
    #   event = LogStash::Event.new({
    #     "message" => "Uploader test log",
    #     "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    #     "oci_la_log_source_name" => "Linux Syslog Logs",
    #     "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
    #     "oci_la_log_set" => nil
    #   })
    #   oci_la_log_group_id = ENV["OCI_TEST_LOG_GROUP_ID"]
    #   records_per_logGroupId = [event]

    #   logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
    #   records_per_logSet_map = logSets_per_logGroupId_map[ENV["OCI_TEST_LOG_GROUP_ID"]]
    #   zippedstream,number_of_records = subject.get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
    #   expect(zippedstream).to be_a(StringIO)
    #   expect(number_of_records).to eq(1)
    # end

    # it "saves to local" do
    #   event = LogStash::Event.new({
    #     "message" => "Uploader test log",
    #     "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    #     "oci_la_log_source_name" => "Linux Syslog Logs",
    #     "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
    #     "oci_la_log_set" => nil
    #   })
    #   oci_la_log_group_id = ENV["OCI_TEST_LOG_GROUP_ID"]
    #   records_per_logGroupId = [event]

    #   logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
    #   records_per_logSet_map = logSets_per_logGroupId_map[ENV["OCI_TEST_LOG_GROUP_ID"]]
    #   zippedstream,number_of_records = subject.get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
      
    #   current_s = Time.now().strftime("%Y%m%dT%H%M%S%9NZ")
    #   subject.save_zip_to_local(oci_la_log_group_id,zippedstream,current_s)
    #   expect(File.exist?('/tmp/record.json')).to be true
    # end
  end
end