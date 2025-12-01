# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/logan"
require "logstash/event"


describe LogStash::Outputs::Logan do
  let(:config) { {
    "namespace" => ENV["OCI_NAMESPACE"] || "namespace",
    "config_file_location" => ENV["OCI_CONFIG_PATH"] || nil,
    "profile_name" => ENV["OCI_PROFILE_NAME"] || "default",
    "dump_zip_file" => true,
    "zip_file_location" => "/tmp/"
  } }
  let(:output) { described_class.new(config) }
  let(:event) { LogStash::Event.new({ "message" => "Test log" }) }
  let(:event_encoded) { "foo" }
  let(:events_and_encoded) { { event => event_encoded } }

  before do
    output.register
  end

  # describe "receive event" do
  #   subject { output.multi_receive_encoded(events_and_encoded) }

  #   it "returns a string" do
  #     expect(subject).to eq("Event received")
  #   end
  # end

  describe "Valid config test" do
    it "initializes client successfuly" do
      output.register
      expect(output.instance_variable_defined?(:@loganalytics_client)).to be true
      expect(output.instance_variable_get(:@loganalytics_client)).not_to be_nil
    end
  end

  describe "invalid configuration test" do
    let(:invalid_config) {{"namespace" => nil}}

    it "fails with LogStash Configuration during initialization" do
      expect {
        described_class.new(invalid_config)
      }.to raise_error(LogStash::ConfigurationError)
    end
    let(:invalid_config2) {{"namespace" => ENV["OCI_NAMESPACE"], "oci_domain" => "hello"}}
    it "fails with invalid domain and namespace #{ENV["OCI_NAMESPACE"]} -" do
      expect {
        described_class.new(invalid_config2)
      }.to raise_error(LogStash::ConfigurationError)
    end
  end
end
