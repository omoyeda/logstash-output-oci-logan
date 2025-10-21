## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require_relative '../../metrics/metricsLabels'
require 'oci/log_analytics/log_analytics'
require 'json'

require 'thread'

class LogGroup
  METRICS_INVALID_REASON_MESSAGE = "MISSING_FIELD_MESSAGE"
  METRICS_INVALID_REASON_LOG_GROUP_ID = "MISSING_OCI_LA_LOG_GROUP_ID_FIELD"
  METRICS_INVALID_REASON_LOG_SOURCE_NAME = "MISSING_OCI_LA_LOG_SOURCE_NAME_FIELD"
  
  def initialize(logger, kubernetes_metadata_keys_mapping)
    @@logger = logger
    @kubernetes_metadata_keys_mapping = kubernetes_metadata_keys_mapping
  end

  def _group_by_logGroupId(events_encoded)
    current = Time.now
    current_f, current_s = current.to_f, current.strftime("%Y%m%dT%H%M%S%9NZ")
    events
    latency = 0
    records_per_tag = 0

    events_encoded.each do |event, encoded|
      next if encoded.nil?
      events << event
    end

    @@logger.debug{"events: #{events.size}"}

    # simple grouping
    lrpes_for_logGroupId = events.group_by { |e| e.get('oci_la_log_group_id')}

    @@logger.debug{"grouped into #{lrpes_for_logGroupId.size} groups"}

    return {}, {}, {}, {}, {}, lrpes_for_logGroupId
  end

  def _group_by_logGroupId(events_encoded)
    @@logger.debug{"MINIMAL VERSION - events_encoded size: #{events_encoded.size}"}

    events_buffer = []
    events_encoded.each do |event, encoded|
      next if encoded.nil?
      events_buffer << event
    end

    @@logger.debug{"events_buffer: #{events_buffer.size}"}

    # simple grouping
    lrpes_for_logGroupId = events_buffer.group_by { |e| e.get('oci_la_log_group_id')}

    @@logger.debug{"grouped into #{lrpes_for_logGroupId.size} groups"}

    return {}, {}, {}, {}, {}, lrpes_for_logGroupId
  end

  def group_by_logGroupId(events_encoded)
    begin
      current = Time.now
      current_f, current_s = current.to_f, current.strftime("%Y%m%dT%H%M%S%9NZ")
      events_buffer = []
      latency = 0
      records_per_tag = 0

      tag_metrics_set = Hash.new
      logGroup_labels_set = Hash.new

      invalid_tag_set = Set.new
      incoming_records_per_tag = Hash.new
      invalid_records_per_tag = Hash.new
      tags_per_logGroupId = Hash.new
      tag_logSet_map = Hash.new
      tag_metadata_map = Hash.new
      timezoneValuesByTag = Hash.new
      incoming_records = 0
      lrpes_for_logGroupId = {}
      
      events_encoded.each do |event, encoded|
        time = event.get('@timestamp').time.to_f
        incoming_records += 1
        metricsLabels = MetricsLabels.new
        if is_valid(encoded)
          begin
            record_hash = event.to_hash
            if record_hash.has_key?("worker_id") && is_valid(event.get("worker_id"))
                metricsLabels.worker_id = event.get("worker_id")# ||= '0'
                @@worker_id = event.get("worker_id")# ||= '0'
            end
            is_tag_exists = false
            if record_hash.has_key?("tag") && is_valid(event.get("tag"))
              is_tag_exists = true
              metricsLabels.tag = event.get("tag")
            end

            if is_tag_exists && incoming_records_per_tag.has_key?(event.get("tag"))
              incoming_records_per_tag[event.get("tag")] += 1
            elsif is_tag_exists
              incoming_records_per_tag[event.get("tag")] = 1
            end
            #For any given tag, if one record fails (mandatory fields validation) then all the records from that source will be ignored
            if is_tag_exists && invalid_tag_set.include?(event.get("tag"))
              invalid_records_per_tag[event.get("tag")] += 1
              next #This tag is already present in the invalid_tag_set, so ignoring the message.
            end
            #Setting tag/default value for oci_la_log_path, when not provided in config file.
            if !record_hash.has_key?("oci_la_log_path") || !is_valid(event.get("oci_la_log_path"))
              if is_tag_exists
                event.set("oci_la_log_path", event.get("tag"))
              else
                event.set("oci_la_log_path", 'UNDEFINED')
              end
            end

            #Extracting oci_la_log_set when oci_la_log_set_key and oci_la_log_set_ext_regex is provided.
            #1) oci_la_log_set param is not provided in config file and above logic not executed.
            #2) Valid oci_la_log_set_key + No oci_la_log_set_ext_regex
              #a) Valid key available in record with oci_la_log_set_key corresponding value  (oci_la_log_set_key is a key in config file) --> oci_la_log_set
              #b) No Valid key available in record with oci_la_log_set_key corresponding value --> nil
            #3) Valid key available in record with oci_la_log_set_key corresponding value + Valid oci_la_log_set_ext_regex
              #a) Parse success --> parsed oci_la_log_set
              #b) Parse failure --> nil (as oci_la_log_set value)
            #4) No oci_la_log_set_key --> do nothing --> nil

            #Extracting oci_la_log_set when oci_la_log_set and oci_la_log_set_ext_regex is provided.
            #1) Valid oci_la_log_set + No oci_la_log_set_ext_regex --> oci_la_log_set
            #2) Valid oci_la_log_set + Valid oci_la_log_set_ext_regex
              #a) Parse success --> parsed oci_la_log_set
              #b) Parse failure --> nil (as oci_la_log_set value)
            #3) No oci_la_log_set --> do nothing --> nil

            unparsed_logSet = nil
            processed_logSet = nil
            if is_tag_exists && tag_logSet_map.has_key?(event.get("tag"))
                event.set("oci_la_log_set", tag_logSet_map[event.get("tag")])
            else
              if record_hash.has_key?("oci_la_log_set_key")
                  if is_valid(event.get("oci_la_log_set_key")) && record_hash.has_key?(event.get("oci_la_log_set_key"))
                      if is_valid(event.get(event.get("oci_la_log_set_key")))
                          unparsed_logSet = event.get(event.get("oci_la_log_set_key"))
                          processed_logSet = get_or_parse_logSet(unparsed_logSet, event, record_hash,is_tag_exists)
                      end
                  end
              end
              if !is_valid(processed_logSet) && record_hash.has_key?("oci_la_log_set")
                  if is_valid(event.get("oci_la_log_set"))
                      unparsed_logSet = event.get("oci_la_log_set")
                      processed_logSet = get_or_parse_logSet(unparsed_logSet, event, record_hash,is_tag_exists)
                  end
              end
              event.set("oci_la_log_set", processed_logSet)
              tag_logSet_map[event.get("tag")] = processed_logSet
            end
            is_valid, metricsLabels.invalid_reason = is_valid_record(record_hash, event)

            unless is_valid
              if is_tag_exists
                invalid_tag_set.add(event.get("tag"))
                invalid_records_per_tag[event.get("tag")] = 1
              end
              next
            end

            metricsLabels.logGroupId = event.get("oci_la_log_group_id")
            metricsLabels.logSourceName = event.get("oci_la_log_source_name")
            if event.get("oci_la_log_set") != nil
                metricsLabels.logSet = event.get("oci_la_log_set")
            end
            event.set("message", json_message_handler("message", event.get("message")))

            #This will check for null or empty messages and only that record will be ignored.
            if !is_valid(event.get("message"))
                metricsLabels.invalid_reason = OutOracleOCILogAnalytics::METRICS_INVALID_REASON_MESSAGE
                if is_tag_exists
                  if invalid_records_per_tag.has_key?(event.get("tag"))
                    invalid_records_per_tag[event.get("tag")] += 1
                  else
                    invalid_records_per_tag[event.get("tag")] = 1
                    @@logger.warn {"'message' field is empty or encoded, Skipping records associated with tag : #{revent.get("tag")}."}
                  end
                else
                  @@logger.warn {"'message' field is empty or encoded, Skipping record."}
                end
                next
            end

            if record_hash.has_key?("kubernetes")
              event.set("oci_la_metadata", get_kubernetes_metadata(event.get("oci_la_metadata"),event))
            end

            if tag_metadata_map.has_key?(event.get("tag"))
              event.set("oci_la_metadata", tag_metadata_map[event.get("tag")])
            else
              if record_hash.has_key?("oci_la_metadata")
                  event.set("oci_la_metadata", get_valid_metadata(event.get("oci_la_metadata")))
                  tags_per_logGroupId[event.get("tag")] = event.get("oci_la_metadata")
              else
                  tags_per_logGroupId[event.get("tag")] = nil
              end
            end

            if is_tag_exists
              if tags_per_logGroupId.has_key?(event.get("oci_la_log_group_id"))
                if !tags_per_logGroupId[event.get("oci_la_log_group_id")].include?(event.get("tag"))
                  tags_per_logGroupId[event.get("oci_la_log_group_id")] += ", "+event.get("tag")
                end
              else
                tags_per_logGroupId[event.get("oci_la_log_group_id")] = event.get("tag")
              end
            end
            # validating the timezone field
            if !timezoneValuesByTag.has_key?(event.get("tag"))
              begin
                timezoneIdentifier = event.get("oci_la_timezone")
                unless is_valid(timezoneIdentifier)
                  event.set("oci_la_timezone", nil)
                else
                  isTimezoneExist = timezone_exist? timezoneIdentifier
                  unless isTimezoneExist
                    @@logger.warn { "Invalid timezone '#{timezoneIdentifier}', using default UTC." }
                    event.set("oci_la_timezone", "UTC")
                  end

                end
                timezoneValuesByTag[event.get("tag")] = event.get("oci_la_timezone")
              end
            else
              event.set("oci_la_timezone", timezoneValuesByTag[event.get("tag")])
            end
            events_buffer << event
          ensure
            # To get chunk_time_to_receive metrics per tag, corresponding latency and total records are calculated
            if tag_metrics_set.has_key?(event.get("tag"))
                metricsLabels = tag_metrics_set[event.get("tag")]
                latency = metricsLabels.latency
                records_per_tag = metricsLabels.records_per_tag
            else
                latency = 0
                records_per_tag = 0
            end
            
            latency += (current_f - time)
            records_per_tag += 1
            
            metricsLabels.latency = latency
            metricsLabels.records_per_tag = records_per_tag
            tag_metrics_set[event.get("tag")] = metricsLabels

            if event.get("oci_la_log_group_id") != nil && !logGroup_labels_set.has_key?(event.get("oci_la_log_group_id"))
                logGroup_labels_set[event.get("oci_la_log_group_id")]  = metricsLabels
            end
          end
        else
          @@logger.trace {"Record is nil, ignoring the record"}
        end
      end

      # tag_metrics_set.each do |tag,metricsLabels|
      #     latency_avg = (metricsLabels.latency / metricsLabels.records_per_tag).round(3)
      #     @@prometheusMetrics.chunk_time_to_receive.observe(latency_avg, labels: { worker_id: metricsLabels.worker_id, tag: tag})
      # end
      events_buffer.group_by{|event|
                  oci_la_log_group_id = event.get('oci_la_log_group_id')
                  (oci_la_log_group_id)
                  }.map {|oci_la_log_group_id, records_per_logGroupId|
                    lrpes_for_logGroupId[oci_la_log_group_id] = records_per_logGroupId
                  }
    rescue => ex
      @@logger.error {"Error occurred while grouping records by oci_la_log_group_id:#{ex.inspect}"}
    end
    return incoming_records_per_tag,invalid_records_per_tag,tag_metrics_set,logGroup_labels_set,tags_per_logGroupId,lrpes_for_logGroupId
  end

  def get_or_parse_logSet(unparsed_logSet, event, record_hash, is_tag_exists)
    oci_la_log_set = nil
    parsed_logSet = nil
    if !is_valid(unparsed_logSet)
        return nil
    end
    if record_hash.has_key?("oci_la_log_set_ext_regex") && is_valid(event.get("oci_la_log_set_ext_regex"))
        parsed_logSet = unparsed_logSet.match(event.get("oci_la_log_set_ext_regex"))
        #*******************************************TO-DO**********************************************************
        # Based on the observed behaviour, below cases are handled. We need to revisit this section.
        # When trying to apply regex on a String and getting a matched substring, observed couple of scenarios.
        # For oci_la_log_set_ext_regex value = '.*\\\\/([^\\\\.]{1,40}).*' this returns an array with both input string and matched pattern
        # For oci_la_log_set_ext_regex value = '[ \\\\w-]+?(?=\\\\.)' this returns an array with only matched pattern
        # For few cases, String is returned instead of an array.
        #*******************************************End of TO-DO***************************************************
        if parsed_logSet!= nil    # Based on the regex pattern, match is returning different outputs for same input.
          if parsed_logSet.is_a? String
            oci_la_log_set = parsed_logSet.encode("UTF-8")  # When matched String is returned instead of an array.
          elsif parsed_logSet.length > 1 #oci_la_log_set_ext_regex '.*\\\\/([^\\\\.]{1,40}).*' this returns an array with both input string and matched pattern
            oci_la_log_set = parsed_logSet[1].encode("UTF-8")
          elsif parsed_logSet.length > 0 # oci_la_log_set_ext_regex '[ \\\\w-]+?(?=\\\\.)' this returns an array with only matched pattern
            oci_la_log_set = parsed_logSet[0].encode("UTF-8") #Encoding to handle escape characters
          else
            oci_la_log_set = nil
          end
        else
          oci_la_log_set = nil
          if is_tag_exists
              @@logger.error {"Error occurred while parsing oci_la_log_set : #{unparsed_logSet} with oci_la_log_set_ext_regex : #{event.get("oci_la_log_set_ext_regex")}. Default oci_la_log_set will be assigned to all the records with tag : #{event.get("tag")}."}
          else
              @@logger.error {"Error occurred while parsing oci_la_log_set : #{unparsed_logSet} with oci_la_log_set_ext_regex : #{event.get("oci_la_log_set_ext_regex")}. Default oci_la_log_set will be assigned."}
          end
        end
    else
        oci_la_log_set = unparsed_logSet.force_encoding('UTF-8').encode("UTF-8")
    end
    return oci_la_log_set
    rescue => ex
          @@logger.error {"Error occurred while parsing oci_la_log_set : #{ex}. Default oci_la_log_set will be assigned."}
          return nil
  end

  def is_valid_record(record_hash,event)
    begin
        invalid_reason = nil
        if !record_hash.has_key?("message")
          invalid_reason = METRICS_INVALID_REASON_MESSAGE
          if record_hash.has_key?("tag")
            @@logger.warn {"Invalid records associated with tag : #{event.get("tag")}. 'message' field is not present in the record."}
          else
            @@logger.info {"InvalidRecord: #{event.to_s}"}
            @@logger.warn {"Invalid record. 'message' field is not present in the record."}
          end
          return false,invalid_reason
        elsif !record_hash.has_key?("oci_la_log_group_id") || !is_valid(event.get("oci_la_log_group_id"))
            invalid_reason = METRICS_INVALID_REASON_LOG_GROUP_ID
            if record_hash.has_key?("tag")
              @@logger.warn {"Invalid records associated with tag : #{event.get("tag")}.'oci_la_log_group_id' must not be empty.
                              Skipping all the records associated with the tag"}
            else
              @@logger.warn {"Invalid record.'oci_la_log_group_id' must not be empty"}
            end
            return false,invalid_reason
        elsif !record_hash.has_key?("oci_la_log_source_name") || !is_valid(event.get("oci_la_log_source_name"))
          invalid_reason = METRICS_INVALID_REASON_LOG_SOURCE_NAME
          if record_hash.has_key?("tag")
            @@logger.warn {"Invalid records associated with tag : #{event.get("tag")}.'oci_la_log_source_name' must not be empty.
                            Skipping all the records associated with the tag"}
          else
            @@logger.warn {"Invalid record.'oci_la_log_source_name' must not be empty"}
          end
          return false,invalid_reason
        else
          return true,invalid_reason
        end
    end
  end

  def flatten(kubernetes_metadata)
    kubernetes_metadata.each_with_object({}) do |(key, value), hash|
      hash[key] = value
      if value.is_a? Hash
        flatten(value).map do |hash_key, hash_value|
          hash["#{key}.#{hash_key}"] = hash_value
        end
      end
    end
  end

  def get_kubernetes_metadata(oci_la_metadata, event)
    # oci_la_metadata -> Hash
    # event -> LogStash::Event
    if oci_la_metadata == nil
      oci_la_metadata = {}
    end
    kubernetes_metadata = flatten(event.get("kubernetes"))
    kubernetes_metadata.each do |key, value|
      if @kubernetes_metadata_keys_mapping.has_key?(key)
          if !is_valid(oci_la_metadata[@kubernetes_metadata_keys_mapping[key]])
            oci_la_metadata[@kubernetes_metadata_keys_mapping[key]] = json_message_handler(key, value)
          end
      end
    end
    return oci_la_metadata
    rescue => ex
      @@logger.error {"Error occurred while getting kubernetes oci_la_metadata:
                        error message: #{ex}"}
      return oci_la_metadata
  end

  def json_message_handler(key, message)
    # key -> String
    # message -> String / Hash
      begin
          if !is_valid(message)
              return nil
          end
          if message.is_a?(Hash)
              # return Yajl.dump(message) #JSON.generate(message)
              return JSON.dump(message)
          end
          return message
      rescue => ex
          @@logger.error {"Error occured while generating json for
                              field: #{key}
                              exception : #{ex}"}
          return nil
      end
  end

  def get_valid_metadata(oci_la_metadata)
    if oci_la_metadata != nil
      if oci_la_metadata.is_a?(Hash)
          valid_metadata = Hash.new
          invalid_keys = []
          oci_la_metadata.each do |key, value|
            if value != nil && !value.is_a?(Hash) && !value.is_a?(Array)
              if key != nil && !key.is_a?(Hash) && !key.is_a?(Array)
                valid_metadata[key] = value
              else
                invalid_keys << key
              end
            else
              invalid_keys << key
            end
          end
          if invalid_keys.length > 0
            @@logger.warn {"Skipping the following oci_la_metadata/oci_la_global_metadata keys #{invalid_keys.compact.reject(&:empty?).join(',')} as the corresponding values are in invalid format."}
          end
          if valid_metadata.length > 0
            return valid_metadata
          else
            return nil
          end
      else
          @@logger.warn {"Ignoring 'oci_la_metadata'/'oci_la_global_metadata' provided in the record_transformer filter as only key-value pairs are supported."}
          return nil
      end
    else
      return nil
    end
  end

  def is_valid(field)
    if field.nil? || field.empty? then
      return false
    else
      return true
    end
  end
end