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

    it "closes cleanly with the dedicated STDOUT logger", :unit_test do
      plugin = described_class.new(config)

      allow(plugin).to receive(:build_loganalytics_client) do
        double("client").tap do |client|
          allow(client).to receive(:upload_log_events_file)
        end
      end

      plugin.register

      expect { plugin.do_close }.not_to raise_error
    end

    it "clears cached clients from the register thread and worker threads", :unit_test do
      plugin = described_class.new(config)
      key = plugin.send(:thread_client_key)
      created_clients = Queue.new

      allow(plugin).to receive(:build_loganalytics_client) do
        Object.new.tap { |client| created_clients << client }
      end

      plugin.register
      register_thread_client = created_clients.pop
      expect(Thread.current.thread_variable_get(key)).to be(register_thread_client)

      worker_thread = Thread.new do
        plugin.send(:client_for_current_thread)
        Thread.current.thread_variable_get(key)
      end
      worker_thread_client = worker_thread.value

      expect(worker_thread_client).not_to be_nil
      expect(worker_thread_client).not_to be(register_thread_client)

      plugin.do_close

      expect(Thread.current.thread_variable_get(key)).to be_nil
      expect(worker_thread.thread_variable_get(key)).to be_nil
    end
  end

  describe "#initialize_logger" do
    it "uses a dedicated STDOUT logger with the configured log level", :unit_test do
      plugin = described_class.new({"namespace" => "example", "plugin_log_level" => "debug"})

      allow(plugin).to receive(:build_loganalytics_client) do
        double("client").tap do |client|
          allow(client).to receive(:upload_log_events_file)
        end
      end

      plugin.register

      logger = plugin.instance_variable_get(:@plugin_logger)
      expect(logger).to be_a(Logger)
      expect(logger.level).to eq(Logger::DEBUG)
    end

    it "includes the current thread id in console log output", :unit_test do
      plugin = described_class.new({"namespace" => "example"})
      output = StringIO.new
      logger = nil

      allow(Logger).to receive(:new).and_wrap_original do |original, target, *args|
        created_logger = original.call(target, *args)
        if target.equal?($stdout)
          created_logger.reopen(output)
          logger = created_logger
        end
        created_logger
      end

      allow(plugin).to receive(:build_loganalytics_client) do
        double("client").tap do |client|
          allow(client).to receive(:upload_log_events_file)
        end
      end

      plugin.register

      worker_thread_id = nil
      Thread.new do
        worker_thread_id = Thread.current.object_id
        logger.info("thread-aware log line")
      end.join

      expect(output.string).to include("[thread-#{worker_thread_id}]")
      expect(output.string).to include("thread-aware log line")
    end
  end
end
