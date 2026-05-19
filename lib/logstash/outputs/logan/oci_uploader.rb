# frozen_string_literal: true

## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require_relative '../../metrics/metrics_labels'
require_relative '../../enums/source'
require_relative '../../dto/log_events_json'
require_relative '../../dto/log_events'

require 'zip'
require 'benchmark'
require 'json'
require 'oci'
require 'logger'
require 'oci/errors'

module LogStash
  module Outputs
    module LogAnalytics
      # Uploader builds ZIP payloads from grouped log events and uploads them to
      # OCI Log Analytics, including retry handling and optional local ZIP dumps.
      # rubocop:disable Metrics/ClassLength, Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/BlockNesting, Metrics/BlockLength, Naming/MethodName, Naming/PredicatePrefix, Naming/VariableName, Naming/BlockParameterName, Naming/MethodParameterName, Style/MultilineTernaryOperator, Style/MultilineBlockChain
      class Uploader
        MAX_FILES_PER_ZIP = 100
        METRICS_SERVICE_ERROR_REASON_400 = 'INVALID_PARAMETER'
        METRICS_SERVICE_ERROR_REASON_401 = 'AUTHENTICATION_FAILED'
        METRICS_SERVICE_ERROR_REASON_404 = 'AUTHORIZATION_FAILED'
        METRICS_SERVICE_ERROR_REASON_429 = 'TOO_MANY_REQUESTES'
        METRICS_SERVICE_ERROR_REASON_500 = 'INTERNAL_SERVER_ERROR'
        METRICS_SERVICE_ERROR_REASON_502 = 'BAD_GATEWAY'
        METRICS_SERVICE_ERROR_REASON_503 = 'SERVICE_UNAVAILABLE'
        METRICS_SERVICE_ERROR_REASON_504 = 'GATEWAY_TIMEOUT'
        METRICS_SERVICE_ERROR_REASON_505 = 'HTTP_VERSION_NOT_SUPPORTED'
        METRICS_SERVICE_ERROR_REASON_UNKNOWN = 'UNKNOWN_ERROR'

        # rubocop:disable Metrics/ParameterLists
        def initialize(namespace, dump_zip_file, client_provider, collection_source, zip_file_location,
                       plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx,
                       retry_wait_on_5xx, retry_max_times_on_5xx, logger)
          @namespace = namespace
          @logger = logger
          @collection_source = collection_source
          @dump_zip_file = dump_zip_file
          @client_provider = client_provider
          @zip_file_location = zip_file_location
          @plugin_retry_on_4xx = plugin_retry_on_4xx
          @plugin_retry_on_5xx = plugin_retry_on_5xx
          @retry_wait_on_4xx = retry_wait_on_4xx
          @retry_max_times_on_4xx = retry_max_times_on_4xx
          @retry_wait_on_5xx = retry_wait_on_5xx
          @retry_max_times_on_5xx = retry_max_times_on_5xx
        end
        # rubocop:enable Metrics/ParameterLists

        # upload zipped stream to oci
        def upload_to_oci(oci_la_log_group_id, number_of_records, zippedstream)
          retry_counts = Hash.new(0)
          result = {
            log_group_id: oci_la_log_group_id,
            number_of_records: number_of_records,
            status: nil,
            error_reason: nil
          }
          begin
            collection_src_prop = getCollectionSource(@collection_source)
            error_reason = nil
            error_code = nil
            opts = { payload_type: 'ZIP', opc_meta_properties: collection_src_prop }
            client = @client_provider.call

            response = client.upload_log_events_file(@namespace,
                                                     oci_la_log_group_id,
                                                     zippedstream.string,
                                                     opts)

            result[:status] = response.status

            if !response.nil? && response.status == 200
              headers = response.headers

              @logger.info("The payload has been successfully uploaded to logAnalytics -\n" \
                           "                              oci_la_log_group_id: #{oci_la_log_group_id},\n" \
                           "                              ConsumedRecords: #{number_of_records},\n" \
                           "                              Date: #{headers['date']},\n" \
                           "                              Time: #{headers['timecreated']},\n" \
                           "                              opc-request-id: #{headers['opc-request-id']},\n" \
                           "                              opc-object-id: #{headers['opc-object-id']}")
            end
          rescue OCI::Errors::ServiceError, OCI::Errors::NetworkError => e
            error_code = e.respond_to?(:status_code) ? e.status_code : e.code
            request_id = e.request_id
            case error_code
            when 400
              error_reason = METRICS_SERVICE_ERROR_REASON_400
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Invalid/Incorrect/missing Parameter - opc-request-id:#{request_id}")
            when 401
              error_reason = METRICS_SERVICE_ERROR_REASON_401
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Not Authenticated.\n" \
                            "                                opc-request-id:#{request_id}\n" \
                            "                                message: #{e.message}")
            when 404
              error_reason = METRICS_SERVICE_ERROR_REASON_404
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            'Authorization failed for given oci_la_log_group_id against given ' \
                            "Tenancy Namespace.\n" \
                            "                                oci_la_log_group_id: #{oci_la_log_group_id}\n" \
                            "                                Namespace: #{@namespace}\n" \
                            "                                opc-request-id:#{request_id}\n" \
                            "                                message: #{e.message}")
            when 429
              error_reason = METRICS_SERVICE_ERROR_REASON_429
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Too Many Requests - opc-request-id:#{request_id}")
            when 500
              error_reason = METRICS_SERVICE_ERROR_REASON_500
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Internal Server Error - opc-request-id:#{request_id}")
            when 502
              error_reason = METRICS_SERVICE_ERROR_REASON_502
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Bad Gateway - opc-request-id:#{request_id}")
            when 503
              error_reason = METRICS_SERVICE_ERROR_REASON_503
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Service unavailable - opc-request-id:#{request_id}")
            when 504
              error_reason = METRICS_SERVICE_ERROR_REASON_504
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "Gateway Timeout - opc-request-id:#{request_id}")
            when 505
              error_reason = METRICS_SERVICE_ERROR_REASON_505
              @logger.error('oci upload exception : Error while uploading the payload. ' \
                            "HTTP Version Not Supported - opc-request-id:#{request_id}")
            else
              error_reason = METRICS_SERVICE_ERROR_REASON_UNKNOWN
              @logger.error("oci upload exception : Error while uploading the payload #{e.message}")
              @logger.error('Raising exception. Not retrying.')
              raise e
            end
            result[:status] = error_code
            result[:error_reason] = error_reason

            # retry only on error codes 4XX
            if error_code.between?(400, 499) && error_code != 429 && @plugin_retry_on_4xx
              if @retry_max_times_on_4xx == -1 || retry_counts[error_code] < @retry_max_times_on_4xx
                retry_counts[error_code] += 1
                attempts = retry_counts[error_code]
                attempt_info =
                  @retry_max_times_on_4xx == -1 ? "#{attempts} of UNLIMITED attempts" :
                                                  "#{attempts} of #{@retry_max_times_on_4xx} attempts"
                @logger.warn("Retrying to upload the payload: #{attempt_info}. Waiting...")
                sleep @retry_wait_on_4xx
                @logger.info('Wait time Over. Retrying...')
                retry
              else
                @logger.error("Failed to upload the payload - status #{error_code}: " \
                              "retried #{retry_counts[error_code]} times")
              end
            end

            # retry only on error codes 5XX
            if error_code.between?(500, 599) && @plugin_retry_on_5xx
              if @retry_max_times_on_5xx == -1 || retry_counts[error_code] < @retry_max_times_on_5xx
                retry_counts[error_code] += 1
                attempts = retry_counts[error_code]
                attempt_info =
                  @retry_max_times_on_5xx == -1 ? "#{attempts} of UNLIMITED attempts" :
                                                  "#{attempts} of #{@retry_max_times_on_5xx} attempts"
                @logger.warn("Retrying to upload the payload: #{attempt_info}. Waiting...")
                sleep @retry_wait_on_5xx
                @logger.info('Wait time Over. Retrying...')
                retry
              else
                @logger.error("Failed to upload the payload - status #{error_code}: " \
                              "retried #{retry_counts[error_code]} times")
              end
            end
          rescue StandardError => e
            error_reason = e
            result[:error_reason] = error_reason
            @logger.error("oci upload exception : Error while uploading the payload. #{e}")
          end
          result
        end

        def show_dropped_messages(incoming_records_per_tag, invalid_records_per_tag, _tag_metrics_set)
          incoming_records_per_tag.each do |key, value|
            dropped_messages = invalid_records_per_tag.key?(key) ? invalid_records_per_tag[key].to_i : 0
            valid_messages = value.to_i - dropped_messages
            if dropped_messages.positive?
              @logger.info("Messages: #{value.to_i} \t Valid: #{valid_messages} \t " \
                           "Invalid: #{dropped_messages} \t tag:#{key}")
            end
          end
        end

        def generate_payload(_tags_per_logGroupId, lrpes_for_logGroupId)
          upload_results = []
          if !lrpes_for_logGroupId.nil? && lrpes_for_logGroupId.length.positive?
            lrpes_for_logGroupId.each do |oci_la_log_group_id, chunks|
              chunks.each do |records_per_logGroupId|
                @logger.info("Generating payload with #{records_per_logGroupId.length} " \
                             " records for oci_la_log_group_id: #{oci_la_log_group_id}")
                zippedstream = nil
                logSets_per_logGroupId_map = {}

                # Only MAX_FILES_PER_ZIP (100) files are allowed, which will be grouped and zipped.
                # Due to MAX_FILES_PER_ZIP constraint, for a oci_la_log_group_id,
                # we can get more than one zip file and those many api calls will be made.
                logSets_per_logGroupId_map, oci_la_global_metadata = get_logSets_map_per_logGroupId(
                  oci_la_log_group_id, records_per_logGroupId
                )
                unless logSets_per_logGroupId_map.nil?
                  Benchmark.measure do
                    logSets_per_logGroupId_map.each_value do |records_per_logSet_map|
                      zippedstream, number_of_records =
                        get_zipped_stream(oci_la_log_group_id, oci_la_global_metadata, records_per_logSet_map)
                      unless zippedstream.nil?
                        zippedstream.rewind # reposition buffer pointer to the beginning
                        upload_results << upload_to_oci(oci_la_log_group_id, number_of_records, zippedstream)
                      end
                    end
                  end.real.round(3)
                end
              ensure
                zippedstream&.close
              end
            end
          end
          upload_results
        end

        # Each oci_la_log_set will correspond to a separate file in the zip
        # Only MAX_FILES_PER_ZIP files are allowed per zip.
        # Here we are grouping logSets so that if file_count reaches MAX_FILES_PER_ZIP, these files will be considered
        #   for a separate zip file.
        def get_logSets_map_per_logGroupId(oci_la_log_group_id, records_per_logGroupId)
          file_count = 0
          oci_la_global_metadata = nil
          is_oci_la_global_metadata_assigned = false
          oci_la_log_set = nil
          records_per_logSet_map = {}
          logSets_per_logGroupId_map = {}

          records_per_logGroupId.group_by do |event|
            unless is_oci_la_global_metadata_assigned
              record_hash = event.to_hash
              oci_la_global_metadata = event.get('oci_la_global_metadata') if record_hash.key?('oci_la_global_metadata')
              is_oci_la_global_metadata_assigned = true
            end
            oci_la_log_set = event.get('oci_la_log_set')
            oci_la_log_set
          end.map do |oci_la_log_set, records_per_logSet|
            records_per_logSet_map = {} if (file_count % MAX_FILES_PER_ZIP).zero?
            records_per_logSet_map[oci_la_log_set] = records_per_logSet
            file_count += 1
            logSets_per_logGroupId_map[file_count] = records_per_logSet_map if (file_count % MAX_FILES_PER_ZIP).zero?
          end
          logSets_per_logGroupId_map[file_count] = records_per_logSet_map
          [logSets_per_logGroupId_map, oci_la_global_metadata]
        rescue StandardError => e
          @logger.error("Error in mapping records to oci_la_log_set.\n" \
                        "                                    oci_la_log_group_id: #{oci_la_log_group_id},\n" \
                        "                                    error message:#{e}")
        end

        def get_zipped_stream(oci_la_log_group_id, oci_la_global_metadata, records_per_logSet_map)
          begin
            current = Time.now
            current_s = current.strftime('%Y%m%dT%H%M%S%9NZ')
            number_of_records = 0
            noOfFilesGenerated = 0
            zippedstream = Zip::OutputStream.write_buffer do |zos|
              records_per_logSet_map.each do |oci_la_log_set, records_per_logSet|
                lrpes_for_logEvents = records_per_logSet.group_by do |event|
                  [
                    event.get('oci_la_metadata'),
                    event.get('oci_la_entity_id'),
                    event.get('oci_la_entity_type'),
                    event.get('oci_la_log_source_name'),
                    event.get('oci_la_log_path'),
                    event.get('oci_la_timezone')
                  ]
                end.map do |lrpe_key, records_per_lrpe|
                  number_of_records += records_per_lrpe.length
                  LogEvents.new(lrpe_key, records_per_lrpe)
                end
                noOfFilesGenerated += 1
                if is_valid(oci_la_log_set)
                  nextEntry = "#{oci_la_log_group_id}_#{current_s}_#{noOfFilesGenerated}" \
                              "_logSet=#{oci_la_log_set}.json"
                  @logger.debug("Added entry #{nextEntry} for oci_la_log_set #{oci_la_log_set} into the zip.")
                else
                  nextEntry = "#{oci_la_log_group_id}_#{current_s}_#{noOfFilesGenerated}.json"
                  @logger.debug("Added entry #{nextEntry} into the zip.")
                end
                zos.put_next_entry(nextEntry)
                logEventsJsonFinal = LogEventsJson.new(oci_la_global_metadata, lrpes_for_logEvents)
                zos.write JSON.dump(logEventsJsonFinal.to_hash)
              end
            end
            zippedstream.rewind
            if @dump_zip_file
              unless is_valid(@zip_file_location)
                @logger.error("dump_zip_file was enabled but zip_file_location was not provided.\n" \
                              '                                  To save zip to local you have to specify a directory.')
              end
              save_zip_to_local(oci_la_log_group_id, zippedstream, current_s)
            end
            # zippedstream.rewind if records.length > 0  #reposition buffer pointer to the beginning
          rescue StandardError => e
            @logger.error("Error in generating payload.\n" \
                          "                              oci_la_log_group_id: #{oci_la_log_group_id},\n" \
                          "                              error message:#{e}")
          end
          [zippedstream, number_of_records]
        end

        def save_zip_to_local(oci_la_log_group_id, zippedstream, current_s)
          fileName = "#{oci_la_log_group_id}_#{current_s}.zip"
          fileLocation = ::File.join(@zip_file_location, fileName)
          file = ::File.open(fileLocation, 'wb')
          file.write(zippedstream.sysread)
          true
        rescue StandardError => e
          @logger.error("Error occurred while saving zip file.\n" \
                        "                              oci_la_log_group_id: #{oci_la_log_group_id},\n" \
                        "                              fileLocation: #{@zip_file_location}\n" \
                        "                              fileName: #{fileName}\n" \
                        "                              error message: #{e}")
          false
        ensure
          file&.close
        end

        # returns a Metadata key and value pair for upload_log_events_file, merely descriptive
        def getCollectionSource(input)
          collections_src = []
          if !is_valid(input)
            collections_src.unshift("source:#{Source::LOGSTASH}")
          elsif input == Source::LOGSTASH.to_s || input == Source::KUBERNETES_SOLUTION.to_s
            collections_src.unshift("source:#{input}")
          else
            # source not define ! using default source 'LOGSTASH'
            collections_src.unshift("source:#{Source::LOGSTASH}")
          end
          collections_src
        end

        def is_valid(field)
          return false if field.nil? || field.empty?

          true
        end
      end
      # rubocop:enable Metrics/ClassLength, Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/BlockNesting, Metrics/BlockLength, Naming/MethodName, Naming/PredicatePrefix, Naming/VariableName, Naming/BlockParameterName, Naming/MethodParameterName, Style/MultilineTernaryOperator, Style/MultilineBlockChain
    end
  end
end
