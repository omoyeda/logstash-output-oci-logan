require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/log_grouper'
require "logstash/event"
require 'logger'

describe LogStash::Outputs::LogAnalytics::LogGroup do
  let(:logger) { Logger.new(STDOUT) }

  # ---- inputs ----
  let(:simple_event) { simple_event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs"
  })}
  let(:event_encoded) { "Uploader test log" }
  let(:event_and_encoded) { { simple_event => event_encoded } }

  # with tag
  let(:tagged_event) { tagged_event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "tag" => "tag_example"
  })}
  let(:tagged_encoded) { "Uploader test log" }
  let(:tagged_and_encoded) { { tagged_event => tagged_encoded } }
  # invalid with tag
  let(:inv_tag_event) { inv_tag_event = LogStash::Event.new({
        "message" => "",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "tag" => "tag_example"
  })}
  let(:inv_tag_encoded) { "Uploader test log" }
  let(:inv_tagged_and_encoded) { { inv_tag_event => inv_tag_encoded } }

  # with metadata
  let(:mdata_event) { tagged_event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "oci_la_metadata" => {"Access Control List" => "test:test"}
  })}
  let(:mdata_encoded) { "Uploader test log" }
  let(:mdata_and_encoded) { { mdata_event => mdata_encoded } }

  # with more than one group ids coming
  # log group id 1
  let(:gid1_event) { gid1_event = LogStash::Event.new({
        "message" => "Uploader test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "oci_la_metadata" => {"Access Control List" => "test:test"},
        "tag" => "tag_example"
  })}
  let(:gid1_encoded) { "Uploader test log" }
  # log group id 2
  let(:gid2_event) { gid2_event = LogStash::Event.new({
        "message" => "Uploader test log N.2",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["LOGAN_LOGGROUP_ID_2"],
        "oci_la_log_set" => "log_set_unit_test_logs_alt",
        "oci_la_metadata" => {"Access Control List" => "foo:foo"},
        "tag" => "alt_tag_example"
  })}
  let(:gid2_encoded) { "Uploader test log N.2" }
  let(:mult_and_encoded) { { gid1_event => gid1_encoded, gid2_event => gid2_encoded } }
  # gid1 with invalid field / missing data
  let(:gid1_event_inv) { gid1_event_inv = LogStash::Event.new({
        "message" => "",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "oci_la_metadata" => {"Access Control List" => "test:test"},
        "tag" => "tag_example"
  })}
  let(:gid1_encoded_inv) { "a" }
  # gid2 with invalid field / missing data
  let(:gid2_event_inv) { gid2_event_inv = LogStash::Event.new({
        "message" => "",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["LOGAN_LOGGROUP_ID_2"],
        "oci_la_log_set" => "log_set_unit_test_logs_alt",
        "oci_la_metadata" => {"Access Control List" => "foo:foo"},
        "tag" => "alt_tag_example"
  })}
  let(:gid2_encoded_inv) { "a" }
  # copies for testing multiple - different tags
  let(:gid1_event_alt) { gid1_event_alt = LogStash::Event.new({
        "message" => "Uploader test log alt",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_set" => "log_set_unit_test_logs",
        "oci_la_metadata" => {"Access Control List" => "test:test"},
        "tag" => "tag_example_ex"
  })}
  let(:gid1_encoded_alt) { "Uploader test log" }
  let(:gid2_event_alt) { gid2_event_alt = LogStash::Event.new({
        "message" => "Uploader test log N.2 alt",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["LOGAN_LOGGROUP_ID_2"],
        "oci_la_log_set" => "log_set_unit_test_logs_alt",
        "oci_la_metadata" => {"Access Control List" => "foo:foo"},
        "tag" => "alt_tag_example_ex"
  })}
  let(:gid2_encoded_alt) { "Uploader test log N.2" }

  let(:mult_and_encoded2) { { gid1_event => gid1_encoded, gid2_event => gid2_encoded, gid1_event_alt => gid1_encoded_alt, gid2_event_alt => gid2_encoded_alt } }
  let(:mult_and_encoded3) { { gid1_event => gid1_encoded, gid2_event => gid2_encoded, gid1_event_inv => gid1_encoded_inv, gid2_event_inv => gid2_encoded_inv } }

  # expected outputs
  # incoming_records_per_tag,invalid_records_per_tag,    ->X- tag_metrics_set,logGroup_labels_set,
  #     tags_per_logGroupId,lrpes_for_logGroupId
  let(:expect_output1) {[
    {}, {}, {nil => nil}, {ENV["OCI_TEST_LOG_GROUP_ID"] => [[simple_event]]}
  ]}

  # needs to add tag
  let(:expect_output2) {[
    {"tag_example" => 1}, {}, {"tag_example" => nil, ENV["OCI_TEST_LOG_GROUP_ID"] => "tag_example"}, {ENV["OCI_TEST_LOG_GROUP_ID"] => [[tagged_event]]}
  ]}
  let(:expect_output3) {[
    {"tag_example" => 1}, {"tag_example" => 1}, {}, {}
  ]}

  # let(:expect_output4) {[
  #   {}, {}, metrics_set, labels_set, {}, {ENV["OCI_TEST_LOG_GROUP_ID"] => [[simple_event]]}
  # ]}

  # w metadata
  let(:expect_output5) {[
    {}, {}, {nil => {"Access Control List" => "test:test"}}, {ENV["OCI_TEST_LOG_GROUP_ID"] => [[mdata_event]]}
  ]}

  # multiple log groups
  let(:expect_output6) {[
    {"tag_example" => 1, "alt_tag_example" => 1}, {}, {"tag_example" => {"Access Control List" => "test:test"},
      ENV["OCI_TEST_LOG_GROUP_ID"] => "tag_example", "alt_tag_example" => {"Access Control List" => "foo:foo"}, ENV["LOGAN_LOGGROUP_ID_2"] => "alt_tag_example"},
      {ENV["OCI_TEST_LOG_GROUP_ID"] => [[gid1_event]], ENV["LOGAN_LOGGROUP_ID_2"] => [[gid2_event]]}
  ]}
  # 2 each with correct fields
  let(:expect_output7) {[
    {"tag_example" => 1, "alt_tag_example" => 1, "tag_example_ex" => 1, "alt_tag_example_ex" => 1}, {}, {"tag_example" => {"Access Control List" => "test:test"},
      ENV["OCI_TEST_LOG_GROUP_ID"] => "tag_example, tag_example_ex", "alt_tag_example" => {"Access Control List" => "foo:foo"},
      ENV["LOGAN_LOGGROUP_ID_2"] => "alt_tag_example, alt_tag_example_ex", "tag_example_ex" => {"Access Control List" => "test:test"}, "alt_tag_example_ex" => {"Access Control List" => "foo:foo"}},
      {ENV["OCI_TEST_LOG_GROUP_ID"] => [[gid1_event, gid1_event_alt]], ENV["LOGAN_LOGGROUP_ID_2"] => [[gid2_event, gid2_event_alt]]}
  ]}
  # 2 each with invalid fields
  let(:expect_output8) {[
    {"tag_example" => 2, "alt_tag_example" => 2}, {"tag_example" => 1, "alt_tag_example" => 1}, {"tag_example" => {"Access Control List" => "test:test"},
      ENV["OCI_TEST_LOG_GROUP_ID"] => "tag_example", "alt_tag_example" => {"Access Control List" => "foo:foo"}, ENV["LOGAN_LOGGROUP_ID_2"] => "alt_tag_example"},
      {ENV["OCI_TEST_LOG_GROUP_ID"] => [[gid1_event]], ENV["LOGAN_LOGGROUP_ID_2"] => [[gid2_event]]}
  ]}

  {nil => {"Access Control List" => "test:test"}}

  subject { described_class.new(logger) }

  context "Testing event inputs" do
    it "does not fail while grouping with group_by_logGroupId" do
      expect{subject.group_by_logGroupId(event_and_encoded)}.not_to raise_error
    end

    it "groups basic event" do
      output = subject.group_by_logGroupId(event_and_encoded)
      expect(output.values_at(0,1,4,5)).to eq(expect_output1)
    end

    it "groups and returns tag events" do
      output = subject.group_by_logGroupId(tagged_and_encoded)
      expect(output.values_at(0,1,4,5)).to eq(expect_output2)
    end

    it "returns invalid tagged events" do
      output = subject.group_by_logGroupId(inv_tagged_and_encoded)
      expect(output.values_at(0,1,4,5)).to eq(expect_output3)
    end

    it "returns grouped events with metadata" do
      output = subject.group_by_logGroupId(mdata_and_encoded)
      expect(output.values_at(0,1,4,5)).to eq(expect_output5)
    end

    it "returns multiple single-grouped events" do
      output = subject.group_by_logGroupId(mult_and_encoded)
      expect(output.values_at(0,1,4,5)).to eq(expect_output6)
    end

    it "returns multiple grouped events, with different tags same group id" do
      output = subject.group_by_logGroupId(mult_and_encoded2)
      # puts "tags---: #{output.values_at(4)}"
      # puts "Is equal? ---: #{expect_output7[2]}"
      # puts "Is equal? ---: #{expect_output7[2] == output.values_at(4)}"
      expect(output.values_at(0,1,4,5)).to eq(expect_output7)
    end
    it "returns multiple grouped events and some invalid ones" do
      output = subject.group_by_logGroupId(mult_and_encoded3)
      expect(output.values_at(0,1,4,5)).to eq(expect_output8)
    end
  end
end