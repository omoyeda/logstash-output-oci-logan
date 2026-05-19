# frozen_string_literal: true

## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require_relative '../../metrics/metrics_labels'
require 'oci/log_analytics/log_analytics'
require 'json'
require 'set'
require 'tzinfo'

# rubocop:disable Style/ClassAndModuleChildren
module LogStash::Outputs::LogAnalytics
  # LogGroup validates incoming events, normalizes log-related fields,
  # and groups records into payload chunks by OCI Log Analytics log group ID.
  # rubocop:disable Metrics/ClassLength
  class LogGroup
    METRICS_INVALID_REASON_MESSAGE = 'MISSING_FIELD_MESSAGE'
    METRICS_INVALID_REASON_LOG_GROUP_ID = 'MISSING_OCI_LA_LOG_GROUP_ID_FIELD'
    METRICS_INVALID_REASON_LOG_SOURCE_NAME = 'MISSING_OCI_LA_LOG_SOURCE_NAME_FIELD'
    METRICS_INVALID_REASON_PAYLOAD_TOO_LARGE = 'EXCEEDED_MAX_PAYLOAD_SIZE'
    METRICS_INVALID_REASON_TIMEZONE = 'INVALID_OCI_LA_TIMEZONE'

    MAX_PAYLOAD_SIZE_BYTES = 2 * 1024 * 1024 # 2 MB

    def initialize(logger)
      @logger = logger
      @warned_validation_failures = Set.new
    end

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/MethodName, Naming/VariableName, Metrics/BlockLength
    def group_by_logGroupId(events_encoded)
      begin
        current = Time.now
        current_f = current.to_f
        _ = current.strftime('%Y%m%dT%H%M%S%9NZ')
        latency = 0
        records_per_tag = 0

        tag_metrics_set = {}
        logGroup_labels_set = {}

        invalid_tag_set = Set.new
        incoming_records_per_tag = {}
        invalid_records_per_tag = {}
        tags_per_logGroupId = {}
        tag_logSet_map = {}
        tag_metadata_map = {}
        grouped = Hash.new { |h, k| h[k] = [] } # log_group_id => [chunks]
        current_chunks = Hash.new { |h, k| h[k] = { size: 0, events: [] } }

        events_encoded.each do |event, encoded|
          time = event.get('@timestamp').time.to_f
          metricsLabels = MetricsLabels.new
          if is_valid(encoded)
            begin
              record_hash = event.to_hash
              if record_hash.key?('worker_id') && is_valid(event.get('worker_id'))
                metricsLabels.worker_id = event.get('worker_id') # ||= '0'
              end
              is_tag_exists = false
              if record_hash.key?('tag') && is_valid(event.get('tag'))
                is_tag_exists = true
                metricsLabels.tag = event.get('tag')
              end

              if is_tag_exists && incoming_records_per_tag.key?(event.get('tag'))
                incoming_records_per_tag[event.get('tag')] += 1
              elsif is_tag_exists
                incoming_records_per_tag[event.get('tag')] = 1
              end
              # For any given tag, if one record fails (mandatory fields validation) then all the records from that
              #   source will be ignored
              if is_tag_exists && invalid_tag_set.include?(event.get('tag'))
                invalid_records_per_tag[event.get('tag')] += 1
                next # This tag is already present in the invalid_tag_set, so ignoring the message.
              end
              # Setting tag/default value for oci_la_log_path, when not provided in config file.
              if !record_hash.key?('oci_la_log_path') || !is_valid(event.get('oci_la_log_path'))
                if is_tag_exists
                  event.set('oci_la_log_path', event.get('tag'))
                else
                  event.set('oci_la_log_path', 'UNDEFINED')
                end
              end

              # Extracting oci_la_log_set when oci_la_log_set_key and oci_la_log_set_ext_regex is provided.
              # 1) oci_la_log_set param is not provided in config file and above logic not executed.
              # 2) Valid oci_la_log_set_key + No oci_la_log_set_ext_regex
              # a) Valid key available in record with oci_la_log_set_key corresponding
              #     value (oci_la_log_set_key is a key in config file) --> oci_la_log_set
              # b) No Valid key available in record with oci_la_log_set_key corresponding value --> nil
              # 3) Valid key available in record with oci_la_log_set_key corresponding value
              #     + Valid oci_la_log_set_ext_regex
              # a) Parse success --> parsed oci_la_log_set
              # b) Parse failure --> nil (as oci_la_log_set value)
              # 4) No oci_la_log_set_key --> do nothing --> nil

              # Extracting oci_la_log_set when oci_la_log_set and oci_la_log_set_ext_regex is provided.
              # 1) Valid oci_la_log_set + No oci_la_log_set_ext_regex --> oci_la_log_set
              # 2) Valid oci_la_log_set + Valid oci_la_log_set_ext_regex
              # a) Parse success --> parsed oci_la_log_set
              # b) Parse failure --> nil (as oci_la_log_set value)
              # 3) No oci_la_log_set --> do nothing --> nil

              nil
              processed_logSet = nil
              if is_tag_exists && tag_logSet_map.key?(event.get('tag'))
                event.set('oci_la_log_set', tag_logSet_map[event.get('tag')])
              else
                if record_hash.key?('oci_la_log_set_key') && is_valid(event.get('oci_la_log_set_key')) &&
                   record_hash.key?(event.get('oci_la_log_set_key')) &&
                   is_valid(event.get(event.get('oci_la_log_set_key')))
                  unparsed_logSet = event.get(event.get('oci_la_log_set_key'))
                  processed_logSet = get_or_parse_logSet(unparsed_logSet, event, record_hash, is_tag_exists)
                end
                if !is_valid(processed_logSet) &&
                   record_hash.key?('oci_la_log_set') &&
                   is_valid(event.get('oci_la_log_set'))
                  unparsed_logSet = event.get('oci_la_log_set')
                  processed_logSet = get_or_parse_logSet(unparsed_logSet, event, record_hash, is_tag_exists)
                end
                event.set('oci_la_log_set', processed_logSet)
                tag_logSet_map[event.get('tag')] = processed_logSet
              end
              is_valid, metricsLabels.invalid_reason = is_valid_record(record_hash, event)

              unless is_valid
                if is_tag_exists
                  invalid_tag_set.add(event.get('tag'))
                  invalid_records_per_tag[event.get('tag')] = 1
                end
                next
              end

              metricsLabels.logGroupId = event.get('oci_la_log_group_id')
              metricsLabels.logSourceName = event.get('oci_la_log_source_name')
              metricsLabels.logSet = event.get('oci_la_log_set') unless event.get('oci_la_log_set').nil?
              event.set('message', json_message_handler('message', event.get('message')))

              # This will check for null or empty messages and only that record will be ignored.
              unless is_valid(event.get('message'))
                metricsLabels.invalid_reason = METRICS_INVALID_REASON_MESSAGE
                # rubocop:disable Metrics/BlockNesting
                if is_tag_exists
                  if invalid_records_per_tag.key?(event.get('tag'))
                    invalid_records_per_tag[event.get('tag')] += 1
                  else
                    invalid_records_per_tag[event.get('tag')] = 1
                    @logger.warn("'message' field is empty or encoded, Skipping records " \
                                 "associated with tag : #{event.get('tag')}.")
                  end
                else
                  @logger.warn("'message' field is empty or encoded, Skipping record.")
                end
                next
                # rubocop:enable Metrics/BlockNesting
              end

              if tag_metadata_map.key?(event.get('tag'))
                event.set('oci_la_metadata', tag_metadata_map[event.get('tag')])
              elsif record_hash.key?('oci_la_metadata')
                event.set('oci_la_metadata', get_valid_metadata(event.get('oci_la_metadata')))
                tags_per_logGroupId[event.get('tag')] = event.get('oci_la_metadata')
              else
                tags_per_logGroupId[event.get('tag')] = nil
              end

              if is_tag_exists
                if tags_per_logGroupId.key?(event.get('oci_la_log_group_id'))
                  # rubocop:disable Metrics/BlockNesting
                  unless tags_per_logGroupId[event.get('oci_la_log_group_id')].include?(event.get('tag'))
                    tags_per_logGroupId[event.get('oci_la_log_group_id')] += ", #{event.get('tag')}"
                  end
                  # rubocop:enable Metrics/BlockNesting
                else
                  tags_per_logGroupId[event.get('oci_la_log_group_id')] = event.get('tag')
                end
              end
              # validating the timezone field per event to avoid inheriting one input's
              # timezone configuration across other events that happen to share a tag.
              timezoneIdentifier = event.get('oci_la_timezone')
              if is_valid(timezoneIdentifier)
                isTimezoneExist = timezone_exist? timezoneIdentifier
                unless isTimezoneExist
                  log_validation_warning_once(record_hash, event, METRICS_INVALID_REASON_TIMEZONE) do
                    @logger.warn("Invalid timezone '#{timezoneIdentifier}', using default UTC.")
                  end
                  event.set('oci_la_timezone', 'UTC')
                end
              else
                event.set('oci_la_timezone', nil)
              end
              # ---- chunk ----
              log_group_id = event.get('oci_la_log_group_id')
              next if log_group_id.nil?

              event_size = event.to_json.bytesize

              if event_size > MAX_PAYLOAD_SIZE_BYTES
                metricsLabels.invalid_reason = METRICS_INVALID_REASON_PAYLOAD_TOO_LARGE
                if is_tag_exists
                  invalid_records_per_tag[event.get('tag')] = invalid_records_per_tag.fetch(event.get('tag'), 0) + 1
                  msg = "Skipping oversized record for tag: #{event.get('tag')}. " \
                    "Event size #{event_size} exceeds max #{MAX_PAYLOAD_SIZE_BYTES}."
                  @logger.warn(msg)
                else
                  @logger.warn("Skipping oversized record. Event size #{event_size} exceeds " \
                               "MAX_PAYLOAD_SIZE_BYTES #{MAX_PAYLOAD_SIZE_BYTES}.")
                end
                next
              end

              # Start a new chunk if needed
              if current_chunks[log_group_id][:size] + event_size > MAX_PAYLOAD_SIZE_BYTES
                @logger.debug('Current chunk is full, starting a new one')
                # finalize current chunk
                unless current_chunks[log_group_id][:events].empty?
                  grouped[log_group_id] << current_chunks[log_group_id][:events]
                end
                # start a new chunk
                current_chunks[log_group_id] = { size: 0, events: [] }
              end

              @logger.debug("Current chunk size: #{current_chunks[log_group_id][:size]}")

              # Add event to current chunk
              current_chunks[log_group_id][:events] << event
              current_chunks[log_group_id][:size] += event_size
            ensure
              # To get chunk_time_to_receive metrics per tag, corresponding latency and total records are calculated
              if tag_metrics_set.key?(event.get('tag'))
                metricsLabels = tag_metrics_set[event.get('tag')]
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
              tag_metrics_set[event.get('tag')] = metricsLabels

              if !event.get('oci_la_log_group_id').nil? && !logGroup_labels_set.key?(event.get('oci_la_log_group_id'))
                logGroup_labels_set[event.get('oci_la_log_group_id')] = metricsLabels
              end
            end
          else
            @logger.trace('Record is nil, ignoring the record')
          end
        end

        # Push any remaining chunks
        current_chunks.each do |log_group_id, chunk|
          grouped[log_group_id] << chunk[:events] unless chunk[:events].empty?
        end
      rescue StandardError => e
        @logger.error("Error occurred while grouping records by oci_la_log_group_id:#{e.inspect}")
      end
      [incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set, logGroup_labels_set, tags_per_logGroupId,
       grouped]
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/MethodName, Naming/VariableName, Metrics/BlockLength

    def timezone_exist?(timezone_identifier)
      TZInfo::Timezone.get(timezone_identifier)
      true
    rescue TZInfo::InvalidTimezoneIdentifier
      false
    end

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/MethodName
    def get_or_parse_logSet(unparsed_log_set, event, record_hash, tag_exists)
      oci_la_log_set = nil
      parsed_log_set = nil
      return nil unless is_valid(unparsed_log_set)

      if record_hash.key?('oci_la_log_set_ext_regex') && is_valid(event.get('oci_la_log_set_ext_regex'))
        parsed_log_set = unparsed_log_set.match(event.get('oci_la_log_set_ext_regex'))
        # *******************************************TO-DO**********************************************************
        # Based on the observed behaviour, below cases are handled. We need to revisit this section.
        # When trying to apply regex on a String and getting a matched substring, observed couple of scenarios.
        # For oci_la_log_set_ext_regex value = '.*\\\\/([^\\\\.]{1,40}).*' this returns an array
        # with both input string and matched pattern
        # For oci_la_log_set_ext_regex value = '[ \\\\w-]+?(?=\\\\.)' this returns an array
        # with only matched pattern
        # For few cases, String is returned instead of an array.
        # *******************************************End of TO-DO***************************************************
        if !parsed_log_set.nil? # Based on the regex pattern, match is returning different outputs for same input.
          # rubocop:disable Style/ConditionalAssignment
          if parsed_log_set.is_a? String
            oci_la_log_set = parsed_log_set.encode('UTF-8') # When matched String is returned instead of an array.
          elsif parsed_log_set.length > 1
            # oci_la_log_set_ext_regex '.*\/([^\.]{1,40}).*'
            # returns an array with both input string and matched pattern
            oci_la_log_set = parsed_log_set[1].encode('UTF-8')
          elsif parsed_log_set.length.positive?
            # oci_la_log_set_ext_regex '[ \\w-]+?(?=\.)'
            # returns an array with only matched pattern
            oci_la_log_set = parsed_log_set[0].encode('UTF-8') # Encoding to handle escape characters
          else
            oci_la_log_set = nil
          end
          # rubocop:enable Style/ConditionalAssignment
        else
          oci_la_log_set = nil
          if tag_exists
            @logger.error("Error occurred while parsing oci_la_log_set : #{unparsed_log_set} with " \
                          "oci_la_log_set_ext_regex : #{event.get('oci_la_log_set_ext_regex')}. " \
                          "Default oci_la_log_set will be assigned to all the records with tag : #{event.get('tag')}.")
          else
            @logger.error("Error occurred while parsing oci_la_log_set : #{unparsed_log_set} with " \
                          "oci_la_log_set_ext_regex : #{event.get('oci_la_log_set_ext_regex')}. " \
                          'Default oci_la_log_set will be assigned.')
          end
        end
      else
        oci_la_log_set = unparsed_log_set.dup.force_encoding('UTF-8').encode('UTF-8')
      end
      oci_la_log_set
    rescue StandardError => e
      @logger.error("Error occurred while parsing oci_la_log_set : #{e}. Default oci_la_log_set will be assigned.")
      nil
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/MethodName

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/PredicatePrefix
    def is_valid_record(record_hash, event)
      invalid_reason = nil
      if !record_hash.key?('message')
        invalid_reason = METRICS_INVALID_REASON_MESSAGE
        if record_hash.key?('tag')
          log_validation_warning_once(record_hash, event, invalid_reason) do
            @logger.warn("Invalid records associated with tag : #{event.get('tag')}. 'message' field is not " \
                         'present in the record. These records will be skipped and will not be added to the payload.')
          end
        else
          @logger.info("InvalidRecord: #{event}")
          log_validation_warning_once(record_hash, event, invalid_reason) do
            @logger.warn("Invalid record. 'message' field is not present in the record. " \
                         'This record will be skipped and will not be added to the payload.')
          end
        end
        [false, invalid_reason]
      elsif !record_hash.key?('oci_la_log_group_id') || !is_valid(event.get('oci_la_log_group_id'))
        invalid_reason = METRICS_INVALID_REASON_LOG_GROUP_ID
        if record_hash.key?('tag')
          log_validation_warning_once(record_hash, event, invalid_reason) do
            @logger.warn("Invalid records associated with tag : #{event.get('tag')}.'oci_la_log_group_id' " \
                         "must not be empty.\nAll records associated with this tag will be skipped and " \
                         'will not be added to the payload.')
          end
        else
          log_validation_warning_once(record_hash, event, invalid_reason) do
            @logger.warn("Invalid record.'oci_la_log_group_id' must not be empty. " \
                         "Records with missing 'oci_la_log_group_id' will be skipped and " \
                         'will not be added to the payload.')
          end
        end
        [false, invalid_reason]
      elsif !record_hash.key?('oci_la_log_source_name') || !is_valid(event.get('oci_la_log_source_name'))
        invalid_reason = METRICS_INVALID_REASON_LOG_SOURCE_NAME
        if record_hash.key?('tag')
          log_validation_warning_once(record_hash, event, invalid_reason) do
            @logger.warn("Invalid records associated with tag : #{event.get('tag')}.'oci_la_log_source_name' " \
                         "must not be empty.\nAll records associated with this tag will be skipped " \
                         'and will not be added to the payload.')
          end
        else
          log_validation_warning_once(record_hash, event, invalid_reason) do
            @logger.warn("Invalid record.'oci_la_log_source_name' must not be empty. " \
                         "Records with missing 'oci_la_log_source_name' will be skipped and " \
                         'will not be added to the payload.')
          end
        end
        [false, invalid_reason]
      else
        [true, invalid_reason]
      end
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/PredicatePrefix

    def log_validation_warning_once(record_hash, event, invalid_reason)
      warning_key = validation_warning_key(record_hash, event, invalid_reason)
      return if @warned_validation_failures.include?(warning_key)

      @warned_validation_failures.add(warning_key)
      yield
    end

    # rubocop:disable Metrics/CyclomaticComplexity
    def validation_warning_key(record_hash, event, invalid_reason)
      context = {}

      record_hash.keys.sort.each do |key|
        next unless key == 'tag' || key == 'worker_id' || key.start_with?('oci_la_')

        value = event.get(key)
        next if value.nil?
        next if value.respond_to?(:empty?) && value.empty?

        context[key] = value
      end

      [invalid_reason, context]
    end
    # rubocop:enable Metrics/CyclomaticComplexity

    def json_message_handler(key, message)
      # key -> String
      # message -> String / Hash

      return nil unless is_valid(message)
      if message.is_a?(Hash)
        # return Yajl.dump(message) #JSON.generate(message)
        return JSON.dump(message)
      end

      message
    rescue StandardError => e
      @logger.error("Error occured while generating json for\n" \
                    "                              field: #{key}\n" \
                    "                              exception : #{e}")
      nil
    end

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
    def get_valid_metadata(oci_la_metadata)
      return nil if oci_la_metadata.nil?

      if oci_la_metadata.is_a?(Hash)
        valid_metadata = {}
        invalid_keys = []
        oci_la_metadata.each do |key, value|
          if !value.nil? && !value.is_a?(Hash) && !value.is_a?(Array)
            if !key.nil? && !key.is_a?(Hash) && !key.is_a?(Array)
              valid_metadata[key] = value
            else
              invalid_keys << key
            end
          else
            invalid_keys << key
          end
        end
        if invalid_keys.length.positive?
          @logger.warn('Skipping the following oci_la_metadata/oci_la_global_metadata keys ' \
                       "#{invalid_keys.compact.reject(&:empty?).join(',')} as the corresponding " \
                       'values are in invalid format.')
        end
        return valid_metadata if valid_metadata.length.positive?

      else
        @logger.warn("Ignoring 'oci_la_metadata'/'oci_la_global_metadata' provided in the " \
                     'record_transformer filter as only key-value pairs are supported.')
      end
      nil
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

    # rubocop:disable Naming/PredicatePrefix
    def is_valid(field)
      return false if field.nil? || field.empty?

      true
    end
    # rubocop:enable Naming/PredicatePrefix
  end
  # rubocop:enable Metrics/ClassLength
end
# rubocop:enable Style/ClassAndModuleChildren
