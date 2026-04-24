# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/log_analytics"
require "logstash/event"
require "stringio"

describe LogStash::Outputs::Logan do
  describe "#register" do
    context "when receiving invalid configuration" do

      let(:invalid_config) {{"namespace" => nil}}
      it "fails with LogStash Configuration during initialization", :unit_test do
        expect {
          described_class.new(invalid_config)
        }.to raise_error(LogStash::ConfigurationError)
      end

      let(:invalid_config2) {{"namespace" => "example", "oci_domain" => "invalid_domain"}}
      it "fails with invalid domain and namespace #{ENV["OCI_NAMESPACE"]} -", :unit_test do
        plugin_fail = described_class.new(invalid_config2)
        expect {
          plugin_fail.register
        }.to raise_error(LogStash::ConfigurationError)
      end

      let(:invalid_config3) {{"namespace" => "example", "dump_zip_file" => true, "zip_file_location" => "/not/a/real/dir"}}
      it "fails when dump_zip_file uses a non-directory path", :unit_test do
        plugin_fail = described_class.new(invalid_config3)
        expect {
          plugin_fail.register
        }.to raise_error(LogStash::ConfigurationError)
      end

      let(:invalid_config4) {{"namespace" => "example", "auth_type" => "BadAuthType"}}
      it "fails when auth_type is invalid", :unit_test do
        plugin_fail = described_class.new(invalid_config4)
        expect {
          plugin_fail.register
        }.to raise_error(LogStash::ConfigurationError, /Invalid authType/)
      end

      let(:invalid_config5) do
        {
          "namespace" => "example",
          "auth_type" => "ConfigFile",
          "config_file_location" => "/tmp/missing-oci-config",
          "profile_name" => "DEFAULT"
        }
      end
      it "fails during register when client initialization fails", :unit_test do
        plugin_fail = described_class.new(invalid_config5)

        allow(OCI::ConfigFileLoader).to receive(:load_config)
          .and_raise(Errno::ENOENT, "No such file or directory")

        expect {
          plugin_fail.register
        }.to raise_error(Errno::ENOENT)
      end

      let(:invalid_config6) do
        {
          "namespace" => "example",
          "auth_type" => "ConfigFile",
          "config_file_location" => nil,
          "profile_name" => "DEFAULT"
        }
      end
      it "fails before client initialization when ConfigFile is missing a config path", :unit_test do
        plugin_fail = described_class.new(invalid_config6)

        expect(plugin_fail).not_to receive(:build_loganalytics_client)

        expect {
          plugin_fail.register
        }.to raise_error(LogStash::ConfigurationError, /invalid config_file_location/)
      end
    end
  end

  describe "#multi_receive_encoded" do
    let(:config) {{"namespace" => "example"}}
    let(:success_response) do
      double("response", status: 200, headers: {
        "date" => "today",
        "timecreated" => "now",
        "opc-request-id" => "opc-req",
        "opc-object-id" => "opc-obj"
      })
    end

    def build_event(message, group_id)
      event = LogStash::Event.new({
        "message" => message,
        "oci_la_entity_id" => "entity",
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => group_id
      })
      timestamp_str = event.get('@timestamp').time.strftime("%b %d %H:%M:%S")
      event.set("message", "#{timestamp_str} test script: #{event.get('message')}")
      event
    end

    it "supports concurrent calls on a shared plugin instance", :unit_test do
      plugin = described_class.new(config)
      uploads = Queue.new

      allow(plugin).to receive(:build_loganalytics_client) do
        client = double("client")
        allow(client).to receive(:upload_log_events_file) do
          uploads << Thread.current.object_id
          success_response
        end
        client
      end

      plugin.register

      payloads = [
        { build_event("thread one", "group-1") => "one" },
        { build_event("thread two", "group-2") => "two" }
      ]

      results = []
      threads = payloads.map do |payload|
        Thread.new do
          results << plugin.multi_receive_encoded(payload)
        end
      end
      threads.each(&:join)

      expect(results.map { |batch| batch.map { |result| result[:status] } }).to all(eq([200]))
      expect(uploads.size).to eq(2)
      expect(uploads.size.times.map { uploads.pop }.uniq.length).to eq(2)
    end
  end

  describe "#do_close" do
    let(:config) {{"namespace" => "example"}}

    it "closes cleanly with the inherited Logstash logger", :unit_test do
      plugin = described_class.new(config)

      allow(plugin).to receive(:build_loganalytics_client) do
        double("client").tap do |client|
          allow(client).to receive(:upload_log_events_file)
        end
      end

      plugin.register

      expect { plugin.do_close }.not_to raise_error
    end
  end
end
