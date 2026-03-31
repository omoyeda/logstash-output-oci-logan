# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/log_analytics"
require "logstash/event"
require "stringio"

describe LogStash::Outputs::Logan do
  let(:config) { {
    "namespace" => ENV["OCI_NAMESPACE"] || "namespace",
    "config_file_location" => ENV["OCI_CONFIG_PATH"] || nil,
    "profile_name" => ENV["OCI_PROFILE_NAME"] || "DEFAULT",
    "dump_zip_file" => true,
    "zip_file_location" => "/tmp/",
    "plugin_retry_on_4xx" => true,
    "retry_wait_on_4xx" => 1,
    "retry_max_times_on_4xx" => 3,
    "plugin_retry_on_5xx" => true,
    "retry_wait_on_5xx" => 1,
    "retry_max_times_on_5xx" => 3,
    "collection_source" => "logstash"
  } }

  let(:config_with_proxy) { {
    "namespace" => ENV["OCI_NAMESPACE"] || "namespace",
    "config_file_location" => ENV["OCI_CONFIG_PATH"] || nil,
    "profile_name" => ENV["OCI_PROFILE_NAME"] || "default",
    "dump_zip_file" => true,
    "zip_file_location" => "/tmp/",
    "plugin_retry_on_4xx" => true,
    "retry_wait_on_4xx" => 1,
    "retry_max_times_on_4xx" => 3,
    "plugin_retry_on_5xx" => true,
    "retry_wait_on_5xx" => 1,
    "retry_max_times_on_5xx" => 3,
    "collection_source" => "logstash",
    "proxy_ip" => ENV["PROXY_IP"],
    "proxy_port" => ENV["PROXY_PORT"]
  } }

  let(:config_with_domain) { {
    "namespace" => ENV["OCI_NAMESPACE"] || "namespace",
    "config_file_location" => ENV["OCI_CONFIG_PATH"] || nil,
    "profile_name" => ENV["OCI_PROFILE_NAME"] || "default",
    "dump_zip_file" => true,
    "zip_file_location" => "/tmp/",
    "plugin_retry_on_4xx" => true,
    "retry_wait_on_4xx" => 1,
    "retry_max_times_on_4xx" => 3,
    "plugin_retry_on_5xx" => true,
    "retry_wait_on_5xx" => 1,
    "retry_max_times_on_5xx" => 3,
    "collection_source" => "logstash",
    "oci_domain" => ENV["OCI_DOMAIN"] || nil
  } }
  
  let(:event) { LogStash::Event.new({
    "message" => "Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"]
  }) }
  let(:event_encoded) { "foo" }
  let(:events_and_encoded) { { event => event_encoded } }

  let(:event_with_metadata) { LogStash::Event.new({
    "message" => "Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
    "oci_la_metadata" => {"Access Control List" => "test:test"}
  }) }
  let(:event_encoded_mdata) { "foo" }
  let(:events_and_encoded_mdata) { { event_with_metadata => event_encoded_mdata } }

  let(:event_with_logset) { LogStash::Event.new({
    "message" => "Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
    "oci_la_log_set" => "log_set_unit_test_logs"
  }) }
  let(:event_encoded_logset) { "foo" }
  let(:events_and_encoded_logset) { { event_with_logset => event_encoded_logset } }

  let(:event_with_tag) { LogStash::Event.new({
    "message" => "Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
    "tag" => "tag_example"
  }) }
  let(:event_encoded_tag) { "foo" }
  let(:events_and_encoded_tag) { { event_with_tag => event_encoded_tag } }

  let(:regex_event) { regex_event = LogStash::Event.new({
        "message" => "Regex test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "oci_la_metadata" => {"Access Control List" => "test:test"},
        "oci_la_log_set_ext_regex" => /(\w+)_/.source
  })}
  let(:regex_encoded) { "Regex test log" }
  let(:regex_and_encoded) { { regex_event => regex_encoded } }

  let(:illegal_event) { LogStash::Event.new({
    "message" => "Illegal Test Log",
    "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
    "oci_la_log_source_name" => "Linux Syslog Logs",
    "oci_la_log_group_id" => "log_group_123_fake"
    }) }
  let(:illegal_event_encoded) { "Illegal Test Log" }
  let(:illegal_events_and_encoded) { { illegal_event => illegal_event_encoded } }

  let(:log_output) { StringIO.new }
  let(:logger) { Logger.new(log_output) }

  subject { described_class.new(config) }

  it 'registers without errors' do
    expect { subject.register }.to_not raise_error
  end

  # receiving events
  describe "#multi_receive_encoded" do
    context "when receiving valid events" do
      before do
        subject.register
      end

      after do
        subject.close
      end

      it "uploads basic event", :integration_test do
        expect { subject.multi_receive_encoded(events_and_encoded) }.to_not raise_error
        expect(subject.oci_uploader.response_status).to eq(200)
      end

      it "uploads event with valid metadata", :integration_test do
        expect { subject.multi_receive_encoded(events_and_encoded_mdata) }.to_not raise_error
        expect(subject.oci_uploader.response_status).to eq(200)
      end

      it "uploads event with valid logset", :integration_test do
        expect { subject.multi_receive_encoded(events_and_encoded_logset) }.to_not raise_error
        expect(subject.oci_uploader.response_status).to eq(200)
      end

      it "uploads event with regex and logset", :integration_test do
        expect { subject.multi_receive_encoded(regex_and_encoded) }.to_not raise_error
        expect(subject.oci_uploader.response_status).to eq(200)
      end

      it "uploads event with valid tag", :integration_test do
        expect { subject.multi_receive_encoded(events_and_encoded_tag) }.to_not raise_error
        expect(subject.oci_uploader.response_status).to eq(200)
      end
    end

    context "when receiving invalid events" do
      before do
        subject.register
        described_class.class_variable_set(:@@logger, logger)
      end

      after do
        subject.close
      end

      context "when invalid record comes in the middle" do
        it "skips only the invalid record", :integration_test do
          subject.multi_receive_encoded(events_and_encoded)
          expect(subject.oci_uploader.response_status).to eq(200)
          subject.multi_receive_encoded(illegal_events_and_encoded)
          expect(subject.oci_uploader.response_status).to eq(404)
          subject.multi_receive_encoded(events_and_encoded_tag)
          expect(subject.oci_uploader.response_status).to eq(200)
        end
      end
    end

    context "when triggering 4xx codes" do
      before do
        subject.register
      end

      after do
        subject.close
      end

      context "with non-existent log group id" do
        it "triggers 404 NotAuthorizedOrNotFound", :integration_test do
          subject.multi_receive_encoded(illegal_events_and_encoded)
          expect(subject.oci_uploader.response_status).to eq(404)
        end
      end
    end

    context "when domain is provided" do
      it "uploads using domain", :integration_test do
        plugin_with_domain = described_class.new(config_with_domain)
        plugin_with_domain.register
        plugin_with_domain.multi_receive_encoded(events_and_encoded)
        expect(plugin_with_domain.oci_uploader.response_status).to eq(200)
      end
    end
  end
end