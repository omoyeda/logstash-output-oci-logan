# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/logan"
require "logstash/event"
require "stringio"

describe LogStash::Outputs::Logan do
  let(:config) { {
    "namespace" => ENV["OCI_NAMESPACE"] || "namespace",
    "config_file_location" => ENV["OCI_CONFIG_PATH"] || nil,
    "profile_name" => ENV["OCI_PROFILE_NAME"] || "default",
    "dump_zip_file" => true,
    "zip_file_location" => "/tmp/"
  } }
  
  # let(:event) { LogStash::Event.new({ "message" => "Test log" }) }
  let(:event) { LogStash::Event.new({
    "message" => "Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"]
  }) }
  let(:event_encoded) { "foo" }
  let(:events_and_encoded) { { event => event_encoded } }

  # invalid events
  let(:inv_event) { LogStash::Event.new({
    "message" => "",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"]
    }) }
  let(:inv_event_encoded) { "Invalid Test Log" }
  let(:inv_events_and_encoded) { { inv_event => inv_event_encoded } }
  
  let(:inv_event2) { LogStash::Event.new({
    "message" => "Invalid Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ""
    }) }
  let(:inv_event_encoded2) { "Invalid Test Log" }
  let(:inv_events_and_encoded2) { { inv_event2 => inv_event_encoded2 } }

  let(:inv_event3) { LogStash::Event.new({
    "message" => "Invalid Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"]
    }) }
  let(:inv_event_encoded3) { "Invalid Test Log" }
  let(:inv_events_and_encoded3) { { inv_event3 => inv_event_encoded3 } }

  let(:log_output) { StringIO.new }
  let(:logger) { Logger.new(log_output) }

  subject { described_class.new(config) }

  context "receiving events" do
    before do
      subject.register
    end

    after do
      subject.close
    end

    # it 'should register without errors' do
    #   expect { subject.register }.to_not raise_error
    # end

    it "receives and uploads event" do
      expect { subject.multi_receive_encoded(events_and_encoded) }.to_not raise_error
    end
  end

  context "Receiving Invalid events" do
    before do
      subject.register
      described_class.class_variable_set(:@@logger, logger)
    end

    after do
      subject.close
    end

    it "receives event with Missing message" do
      subject.multi_receive_encoded(inv_events_and_encoded)
      log_output.rewind
      expect(log_output.read).to include("'message' field is empty or encoded, Skipping record.")
    end

    it "receives event with Missing Log Group" do
      subject.multi_receive_encoded(inv_events_and_encoded2)
      log_output.rewind
      expect(log_output.read).to include("Invalid record.'oci_la_log_group_id' must not be empty")
    end

    it "receives event with Missing Log Source name" do
      subject.multi_receive_encoded(inv_events_and_encoded3)
      log_output.rewind
      expect(log_output.read).to include("Invalid record.'oci_la_log_source_name' must not be empty")
    end
  end

  # describe "Plugin receives invalid records" do
  #   it "Receives missing oci_la_log_group_id" do
  #     subject.register
  #     expect { subject.multi_receive_encoded(inv_events_and_encoded) }.to_not raise_error
  #     subject.close
  #   end
  # end

  describe "invalid configuration test" do
    let(:invalid_config) {{"namespace" => nil}}

    it "fails with LogStash Configuration during initialization" do
      expect {
        described_class.new(invalid_config)
      }.to raise_error(LogStash::ConfigurationError)
    end

    let(:invalid_config2) {{"namespace" => ENV["OCI_NAMESPACE"], "oci_domain" => "invalid_domain"}}
    it "fails with invalid domain and namespace #{ENV["OCI_NAMESPACE"]} -" do
      plugin_fail = described_class.new(invalid_config2)
      expect {
        plugin_fail.register
      }.to raise_error(LogStash::ConfigurationError)
    end
  end

  # describe "" do
    
  # end
end
