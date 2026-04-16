# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/log_analytics"

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
    end
  end
end
