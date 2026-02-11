require "logstash/devutils/rspec/spec_helper"
require 'logstash/outputs/logan/log_grouper'
require "logstash/event"
require 'logger'

describe LogStash::Outputs::LogAnalytics::LogGroup do
  let(:logger) { Logger.new(STDOUT) }

  # ---- inputs ----
  let(:minimal_field_event) { minimal_field_event = LogStash::Event.new({
        "message" => "Minimum field test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
  })}

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

  let(:logpath_event) { logpath_event = LogStash::Event.new({
        "message" => "Log Path test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_path" => "some_log_path"
  })}
  let(:logpath_encoded) { "Log Path test log" }
  let(:logpath_and_encoded) { { logpath_event => logpath_encoded } }

  let(:logpath_tag_event) { logpath_tag_event = LogStash::Event.new({
        "message" => "Log Path test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_path" => "",
        "tag" => "tag_for_log_path"
  })}
  let(:logpath_tag_encoded) { "Log Path test log" }
  let(:logpath_tag_and_encoded) { { logpath_tag_event => logpath_tag_encoded } }

  let(:empty_logpath_event) { empty_logpath_event = LogStash::Event.new({
        "message" => "Log Path test log",
        "oci_la_entity_id" => ENV["OCI_TEST_ENTITY_ID"],
        "oci_la_log_source_name" => "Linux Syslog Logs",
        "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        "oci_la_log_path" => ""
  })}
  let(:empty_logpath_encoded) { "Log Path test log" }
  let(:empty_logpath_and_encoded) { { empty_logpath_event => empty_logpath_encoded } }

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
  let(:mdata_event) { mdata_event = LogStash::Event.new({
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

  # **** Expected Outputs for parse log set ****
  let(:expect_output9) { "log_set_unit_test" }

  subject { described_class.new(logger) }

  describe "#group_by_logGroupId" do
    context "when grouping by log group id" do
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
        expect(output.values_at(0,1,4,5)).to eq(expect_output7)
      end
      it "returns multiple grouped events and some invalid ones" do
        output = subject.group_by_logGroupId(mult_and_encoded3)
        expect(output.values_at(0,1,4,5)).to eq(expect_output8)
      end

      it "returns grouped events with parsed log set" do
        output = subject.group_by_logGroupId(regex_and_encoded)
        expect(output[5][ENV["OCI_TEST_LOG_GROUP_ID"]][0][0].get("oci_la_log_set")).to eq(expect_output9)
      end
    end
    context "when providing optional fields" do
      it "returns grouped event with log path" do
        output = subject.group_by_logGroupId(logpath_and_encoded)
        expect(output[5][ENV["OCI_TEST_LOG_GROUP_ID"]][0][0].get("oci_la_log_path")).to eq('some_log_path')
      end
      it "sets UNDEFINED to empty log path" do
        output = subject.group_by_logGroupId(empty_logpath_and_encoded)
        expect(output[5][ENV["OCI_TEST_LOG_GROUP_ID"]][0][0].get("oci_la_log_path")).to eq('UNDEFINED')
      end
      it "sets tag to empty log path" do
        output = subject.group_by_logGroupId(logpath_tag_and_encoded)
        expect(output[5][ENV["OCI_TEST_LOG_GROUP_ID"]][0][0].get("oci_la_log_path")).to eq('tag_for_log_path')
      end
    end
  end

  describe "#get_or_parse_logSet" do
    context "when log sets are valid" do
      # input order -> get_or_parse_logSet(unparsed_logSet, event, record_hash, is_tag_exists)
      it "returns same log set while parsing log set without tag" do
        expect(subject.get_or_parse_logSet(
          "log_set_unit_test_logs", simple_event, simple_event.to_hash, false
        )).to eq("log_set_unit_test_logs")
      end
      it "returns parsed logset while without tag" do
        expect(subject.get_or_parse_logSet(
          "oci_set_example", regex_event, regex_event.to_hash, false
        )).to eq("oci_set")
      end
    end
    context "when log sets are invalid" do
      it "returns nil while parsing log set without tag" do
        expect(subject.get_or_parse_logSet(
          "", simple_event, simple_event.to_hash, false
        )).to be_nil
      end
    end
  end

  describe "#is_valid_record" do
    context "when records are valid" do
      it "returns true for a field complete record" do
        expect(subject.is_valid_record(simple_event.to_hash,simple_event)).to eq([true, nil])
      end
    end
    context "when records are not valid" do
      it "returns false for missing/invalid log group id" do
        invalid_loggroup_event = LogStash::Event.new({
          "message" => "Test log",
          "oci_la_log_source_name" => "Linux Syslog Logs",
          "oci_la_log_group_id" => nil,
        })
        expect(subject.is_valid_record(invalid_loggroup_event.to_hash,invalid_loggroup_event)).to eq([false, "MISSING_OCI_LA_LOG_GROUP_ID_FIELD"])
      end
      it "returns false for missing/invalid log source name" do
        invalid_loggroup_event = LogStash::Event.new({
          "message" => "Test log",
          "oci_la_log_source_name" => "",
          "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        })
        expect(subject.is_valid_record(invalid_loggroup_event.to_hash,invalid_loggroup_event)).to eq([false, "MISSING_OCI_LA_LOG_SOURCE_NAME_FIELD"])
      end
      it "returns false for missing/invalid message in record" do
        invalid_loggroup_event = LogStash::Event.new({
          "oci_la_log_source_name" => "Linux Syslog Logs",
          "oci_la_log_group_id" => ENV["OCI_TEST_LOG_GROUP_ID"],
        })
        expect(subject.is_valid_record(invalid_loggroup_event.to_hash,invalid_loggroup_event)).to eq([false, "MISSING_FIELD_MESSAGE"])
      end
    end
  end

  describe "#get_valid_metadata" do
    context "when extracting valid metadata" do
      it "only accepts Hash metadata" do
        metadata = [{"Access Control List" => "test:test"}]
        expect(subject.get_valid_metadata(metadata)).to eq(nil)
      end
      it "returns the metadata" do
        metadata = {"Access Control List" => "test:test", "Something" => 123}
        expect(subject.get_valid_metadata(metadata)).to eq({"Access Control List" => "test:test", "Something" => 123})
      end
    end
    context "when receiving invalid metadata" do
      it "does not accept (skip) array or Hash key/values" do
        metadata = {"Something" => "Other", "ResourcesID" => ["ocid123", "ocid456"]}
        expect(subject.get_valid_metadata(metadata)).to eq({"Something" => "Other"})

        metadata = {"Sources" => {"id" => "ocid123"}, "Access Control List" => "foo:foo"}
        expect(subject.get_valid_metadata(metadata)).to eq({"Access Control List" => "foo:foo"})

        metadata = {"Access Control List" => "foo:foo", [1,"foo"] => "something"}
        expect(subject.get_valid_metadata(metadata)).to eq({"Access Control List" => "foo:foo"})

        metadata = {{"Number" => 2} => "something"}
        expect(subject.get_valid_metadata(metadata)).to eq(nil)
      end
    end
  end
end