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
  
  let(:event) { LogStash::Event.new({ "message" => "Test log" }) }
  let(:event_encoded) { "foo" }
  let(:events_and_encoded) { { event => event_encoded } }

  subject { described_class.new(config) }

  before do
    # subject.register
  end

  it 'should register without errors' do
    expect { subject.register }.to_not raise_error

    subject.close
  end

  # describe "receive event" do
  #   subject { output.multi_receive_encoded(events_and_encoded) }

  #   it "returns a string" do
  #     expect(subject).to eq("Event received")
  #   end
  # end

  # describe "Valid config test" do
  #   it "initializes client successfuly" do
  #     logan = described_class.new(config)
  #     logan.register
  #     expect(subject.instance_variable_get(:@client)).not_to be nil
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
