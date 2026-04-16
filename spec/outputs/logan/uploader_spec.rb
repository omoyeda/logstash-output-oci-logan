require 'oci/log_analytics/log_analytics_client'
require 'oci/regions'
require 'oci/config'

require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/oci_uploader'
require "logstash/event"
require 'logger'
require 'tmpdir'

describe LogStash::Outputs::LogAnalytics::Uploader do
  namespace = "OCI_NAMESPACE"
  dump_zip_file = true
  loganalytics_client = OCI::LogAnalytics::LogAnalyticsClient.new()
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
  let(:event) { event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => "OCI_TEST_ENTITY_ID",
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => "OCI_TEST_LOG_GROUP_ID",
        "oci_la_log_set" => "log_set_unit_test_logs"
      }) }

  let(:event_with_metadata) { event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => "OCI_TEST_ENTITY_ID",
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => "OCI_TEST_LOG_GROUP_ID",
        "oci_la_log_set" => "log_set_unit_test_logs",
        "oci_la_global_metadata" => {"Access Control List" => "test:test"}
      }) }

  subject { described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
        zip_file_location, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx,
        retry_wait_on_5xx, retry_max_times_on_5xx, logger) }

  describe "#generate_payload" do
    context "with sample logs" do
      it "does not fail while generating payload", :unit_test do
        tags_per_logGroupId = { "OCI_TEST_LOG_GROUP_ID" => "" }
        lrpes_for_logGroupId = { "OCI_TEST_LOG_GROUP_ID" => [[event]] }
        expect { subject.generate_payload(tags_per_logGroupId, lrpes_for_logGroupId) }.not_to raise_error
      end
    end
  end

  context "testing function return formats" do
    describe "#get_logSets_map_per_logGroupId" do
      it "returns only log sets Hash", :unit_test do
        oci_la_log_group_id = "OCI_TEST_LOG_GROUP_ID"
        records_per_logGroupId = [event]
        
        logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
        expect(logSets_per_logGroupId_map).to be_a(Hash)
        expect(oci_la_global_metadata).to be_nil
      end

      it "returns metadata Hash", :unit_test do
        oci_la_log_group_id = "OCI_TEST_LOG_GROUP_ID"
        records_per_logGroupId = [event_with_metadata]
        
        logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
        expect(oci_la_global_metadata['Access Control List']).to eq("test:test")
      end
    end

    describe "#get_zipped_stream" do
      it "returns zippedstream for payload", :unit_test do
        oci_la_log_group_id = "OCI_TEST_LOG_GROUP_ID"
        records_per_logGroupId = [event]

        logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
        records_per_logSet_map = logSets_per_logGroupId_map[1]
        zippedstream,number_of_records = subject.get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
        expect(zippedstream).to be_a(StringIO)
        expect(number_of_records).to eq(1)
      end

      it "returns zip stream with 2 or more events", :unit_test do
        oci_la_log_group_id = "OCI_TEST_LOG_GROUP_ID"
        records_per_logGroupId = [event, event, event]

        logSets_per_logGroupId_map,oci_la_global_metadata = subject.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
        records_per_logSet_map = logSets_per_logGroupId_map[1]
        zippedstream,number_of_records = subject.get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
        expect(number_of_records).to eq(3)
      end
    end

    describe "#getCollectionSource" do
      it "returns logstash collection source", :unit_test do
        expect(subject.getCollectionSource(Source::LOGSTASH)).to eq(["source:logstash"])
      end
      it "returns kubernetes collection source", :unit_test do
        expect(subject.getCollectionSource("kubernetes_solution")).to eq(["source:kubernetes_solution"])
      end
      context "when input invalid source it returns logstash source", :unit_test do
        it {expect(subject.getCollectionSource("anything")).to eq(["source:logstash"])}
      end
    end
  end

  describe "#save_zip_to_local" do
    context "when zip_file_location is provided" do
      it "saves to local", :unit_test do
        Dir.mktmpdir do |directory|
          uploader = described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
            directory, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx,
            retry_wait_on_5xx, retry_max_times_on_5xx, logger)

          oci_la_log_group_id = "OCI_TEST_LOG_GROUP_ID"
          records_per_logGroupId = [event]

          logSets_per_logGroupId_map,oci_la_global_metadata = uploader.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
          records_per_logSet_map = logSets_per_logGroupId_map[1]
          zippedstream,number_of_records = uploader.get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
          
          current_s = Time.now().strftime("%Y%m%dT%H%M%S%9NZ")
          uploader.save_zip_to_local(oci_la_log_group_id,zippedstream,current_s)
          file_name = oci_la_log_group_id+ "_#{current_s}.zip"
          expect(File.exist?(File.join(directory, file_name))).to be true
        end
      end
    end
    context "when zip_file_location is not provided" do
      it "does not save zip file locally", :unit_test do
        no_file_location_uploader = described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
        nil, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx,
        retry_wait_on_5xx, retry_max_times_on_5xx, logger)
        
        oci_la_log_group_id = "OCI_TEST_LOG_GROUP_ID"
        records_per_logGroupId = [event]

        logSets_per_logGroupId_map,oci_la_global_metadata = no_file_location_uploader.get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
        records_per_logSet_map = logSets_per_logGroupId_map[1]
        zippedstream,number_of_records = no_file_location_uploader.get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
        
        current_s = Time.now().strftime("%Y%m%dT%H%M%S%9NZ")
        no_file_location_uploader.save_zip_to_local(oci_la_log_group_id,zippedstream,current_s)
        expect(no_file_location_uploader.saved_to_local).to eq(false)
      end
    end
  end

  describe "#upload_to_oci" do
    context "when retrying different HTTP status codes" do
      it "tracks retries independently per status code", :unit_test do
        uploader = described_class.new(namespace, dump_zip_file, loganalytics_client, collection_source,
          zip_file_location, true, true, 0, 2, 0, 2, logger)

        success_response = double("response", status: 200, headers: {
          "date" => "today",
          "timecreated" => "now",
          "opc-request-id" => "opc-req",
          "opc-object-id" => "opc-obj"
        })

        errors = [
          OCI::Errors::ServiceError.new(500, "InternalServerError", "req-1", "boom"),
          OCI::Errors::ServiceError.new(500, "InternalServerError", "req-2", "boom"),
          OCI::Errors::ServiceError.new(504, "GatewayTimeout", "req-3", "boom"),
          success_response
        ]

        allow(loganalytics_client).to receive(:upload_log_events_file) do
          result = errors.shift
          raise result if result.is_a?(Exception)
          result
        end

        uploader.upload_to_oci("OCI_TEST_LOG_GROUP_ID", 1, StringIO.new("zip"))

        expect(loganalytics_client).to have_received(:upload_log_events_file).exactly(4).times
        expect(uploader.response_status).to eq(200)
      end
    end
  end
end
