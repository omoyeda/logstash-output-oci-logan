## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require_relative '../../metrics/metricsLabels'
require_relative '../../enums/source'
require_relative '../../dto/logEventsJson'
require_relative '../../dto/logEvents'

require 'zip'
require "benchmark"
require 'json'
require 'oci'
require 'logger'
require 'oci/errors'

module LogStash
  module Outputs
    module LogAnalytics
      class Uploader
        MAX_FILES_PER_ZIP = 100
        METRICS_SERVICE_ERROR_REASON_400 = "INVALID_PARAMETER"
        METRICS_SERVICE_ERROR_REASON_401 = "AUTHENTICATION_FAILED"
        METRICS_SERVICE_ERROR_REASON_404 = "AUTHORIZATION_FAILED"
        METRICS_SERVICE_ERROR_REASON_429 = "TOO_MANY_REQUESTES"
        METRICS_SERVICE_ERROR_REASON_500 = "INTERNAL_SERVER_ERROR"
        METRICS_SERVICE_ERROR_REASON_502 = "BAD_GATEWAY"
        METRICS_SERVICE_ERROR_REASON_503 = "SERVICE_UNAVAILABLE"
        METRICS_SERVICE_ERROR_REASON_504 = "GATEWAY_TIMEOUT"
        METRICS_SERVICE_ERROR_REASON_505 = "HTTP_VERSION_NOT_SUPPORTED"
        METRICS_SERVICE_ERROR_REASON_UNKNOWN = "UNKNOWN_ERROR"

        def initialize(namespace, dump_zip_file, client_provider, collection_source, zip_file_location, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx, retry_wait_on_5xx, retry_max_times_on_5xx, logger)
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
            opts = { payload_type: "ZIP", opc_meta_properties: collection_src_prop }
            client = @client_provider.call
            
            response = client.upload_log_events_file(namespace_name=@namespace,
                                            logGroupId=oci_la_log_group_id ,
                                            uploadLogEventsFileDetails=zippedstream.string,
                                            opts)

            result[:status] = response.status

            if !response.nil?  && response.status == 200 then
              headers = response.headers

              @logger.info("The payload has been successfully uploaded to logAnalytics -\n                              oci_la_log_group_id: #{oci_la_log_group_id},\n                              ConsumedRecords: #{number_of_records},\n                              Date: #{headers['date']},\n                              Time: #{headers['timecreated']},\n                              opc-request-id: #{headers['opc-request-id']},\n                              opc-object-id: #{headers['opc-object-id']}")
            end
          rescue OCI::Errors::ServiceError, OCI::Errors::NetworkError => error
            error_code = error.respond_to?(:status_code) ? error.status_code : error.code
            request_id = error.request_id
            case error_code
              when 400
                error_reason = METRICS_SERVICE_ERROR_REASON_400
                @logger.error("oci upload exception : Error while uploading the payload. Invalid/Incorrect/missing Parameter - opc-request-id:#{request_id}")
              when 401
                error_reason = METRICS_SERVICE_ERROR_REASON_401
                @logger.error("oci upload exception : Error while uploading the payload. Not Authenticated.\n                                opc-request-id:#{request_id}\n                                message: #{error.message}")
              when 404
                error_reason = METRICS_SERVICE_ERROR_REASON_404
                @logger.error("oci upload exception : Error while uploading the payload. Authorization failed for given oci_la_log_group_id against given Tenancy Namespace.\n                                oci_la_log_group_id: #{oci_la_log_group_id}\n                                Namespace: #{@namespace}\n                                opc-request-id:#{request_id}\n                                message: #{error.message}")
              when 429
                error_reason = METRICS_SERVICE_ERROR_REASON_429
                @logger.error("oci upload exception : Error while uploading the payload. Too Many Requests - opc-request-id:#{request_id}")
              when 500
                error_reason = METRICS_SERVICE_ERROR_REASON_500
                @logger.error("oci upload exception : Error while uploading the payload. Internal Server Error - opc-request-id:#{request_id}")
              when 502
                error_reason = METRICS_SERVICE_ERROR_REASON_502
                @logger.error("oci upload exception : Error while uploading the payload. Bad Gateway - opc-request-id:#{request_id}")
              when 503
                error_reason = METRICS_SERVICE_ERROR_REASON_503
                @logger.error("oci upload exception : Error while uploading the payload. Service unavailable - opc-request-id:#{request_id}")
              when 504
                error_reason = METRICS_SERVICE_ERROR_REASON_504
                @logger.error("oci upload exception : Error while uploading the payload. Gateway Timeout - opc-request-id:#{request_id}")
              when 505
                error_reason = METRICS_SERVICE_ERROR_REASON_505
                @logger.error("oci upload exception : Error while uploading the payload. HTTP Version Not Supported - opc-request-id:#{request_id}")
              else
                error_reason = METRICS_SERVICE_ERROR_REASON_UNKNOWN
                @logger.error("oci upload exception : Error while uploading the payload #{error.message}")
                @logger.error("Raising exception. Not retrying.")
                raise error
            end
            result[:status] = error_code
            result[:error_reason] = error_reason

            # retry only on error codes 4XX
            if error_code.between?(400,499) && error_code != 429 && @plugin_retry_on_4xx
              if @retry_max_times_on_4xx == -1 || retry_counts[error_code] < @retry_max_times_on_4xx
                retry_counts[error_code] += 1
                attempts = retry_counts[error_code]
                attempt_info = @retry_max_times_on_4xx == -1 ? "#{attempts} of UNLIMITED attempts" : "#{attempts} of #{@retry_max_times_on_4xx} attempts"
                @logger.warn("Retrying to upload the payload: #{attempt_info}. Waiting...")
                sleep @retry_wait_on_4xx
                @logger.info("Wait time Over. Retrying...")
                retry
              else
                @logger.error("Failed to upload the payload - status #{error_code}: retried #{retry_counts[error_code]} times")
              end
            end

            # retry only on error codes 5XX
            if error_code.between?(500,599) && @plugin_retry_on_5xx
              if @retry_max_times_on_5xx == -1 || retry_counts[error_code] < @retry_max_times_on_5xx
                retry_counts[error_code] += 1
                attempts = retry_counts[error_code]
                attempt_info = @retry_max_times_on_5xx == -1 ? "#{attempts} of UNLIMITED attempts" : "#{attempts} of #{@retry_max_times_on_5xx} attempts"
                @logger.warn("Retrying to upload the payload: #{attempt_info}. Waiting...")
                sleep @retry_wait_on_5xx
                @logger.info("Wait time Over. Retrying...")
                retry
              else
                @logger.error("Failed to upload the payload - status #{error_code}: retried #{retry_counts[error_code]} times")
              end
            end
          rescue => ex
            error_reason = ex
            result[:error_reason] = error_reason
            @logger.error("oci upload exception : Error while uploading the payload. #{ex}")
          end
          result
        end

        def show_dropped_messages(incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set)
          incoming_records_per_tag.each do |key,value|
            dropped_messages = (invalid_records_per_tag.has_key?(key)) ? invalid_records_per_tag[key].to_i : 0
            valid_messages = value.to_i - dropped_messages
            if dropped_messages > 0
              @logger.info("Messages: #{value.to_i} \t Valid: #{valid_messages} \t Invalid: #{dropped_messages} \t tag:#{key}")
            end
          end
        end

        def generate_payload(tags_per_logGroupId, lrpes_for_logGroupId)
          upload_results = []
          if lrpes_for_logGroupId != nil && lrpes_for_logGroupId.length > 0
            lrpes_for_logGroupId.each do |oci_la_log_group_id, chunks|
              chunks.each do |records_per_logGroupId|
                begin
                  tags = tags_per_logGroupId.key(oci_la_log_group_id)
                  @logger.info("Generating payload with #{records_per_logGroupId.length}  records for oci_la_log_group_id: #{oci_la_log_group_id}")
                  zippedstream = nil
                  oci_la_log_set = nil
                  logSets_per_logGroupId_map = Hash.new

                  # Only MAX_FILES_PER_ZIP (100) files are allowed, which will be grouped and zipped.
                  # Due to MAX_FILES_PER_ZIP constraint, for a oci_la_log_group_id, we can get more than one zip file and those many api calls will be made.
                  logSets_per_logGroupId_map, oci_la_global_metadata = get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
                    if logSets_per_logGroupId_map != nil
                      bytes_out = 0
                      records_out = 0
                      chunk_upload_time_taken = nil
                      chunk_upload_time_taken = Benchmark.measure {
                        logSets_per_logGroupId_map.each do |file_count,records_per_logSet_map|
                            zippedstream,number_of_records = get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
                            if zippedstream != nil
                              zippedstream.rewind #reposition buffer pointer to the beginning
                              upload_results << upload_to_oci(oci_la_log_group_id, number_of_records, zippedstream)
                            end
                        end
                      }.real.round(3)
                    end
                ensure
                  zippedstream&.close
                end
              end
            end
          end
          upload_results
        end

        # Each oci_la_log_set will correspond to a separate file in the zip
        # Only MAX_FILES_PER_ZIP files are allowed per zip.
        # Here we are grouping logSets so that if file_count reaches MAX_FILES_PER_ZIP, these files will be considered for a separate zip file.
        def get_logSets_map_per_logGroupId(oci_la_log_group_id,records_per_logGroupId)
            file_count = 0
            oci_la_global_metadata = nil
            is_oci_la_global_metadata_assigned = false
            oci_la_log_set = nil
            records_per_logSet_map = Hash.new
            logSets_per_logGroupId_map = Hash.new

            records_per_logGroupId.group_by { |event|
              if !is_oci_la_global_metadata_assigned
                record_hash = event.to_hash
                if record_hash.has_key?("oci_la_global_metadata")
                  oci_la_global_metadata = event.get('oci_la_global_metadata')
                end
                is_oci_la_global_metadata_assigned = true
              end
              oci_la_log_set = event.get('oci_la_log_set')
              (oci_la_log_set)
            }.map { |oci_la_log_set, records_per_logSet|
                if file_count % MAX_FILES_PER_ZIP == 0
                    records_per_logSet_map = Hash.new
                end
                records_per_logSet_map[oci_la_log_set] = records_per_logSet
                file_count += 1
                if file_count % MAX_FILES_PER_ZIP == 0
                    logSets_per_logGroupId_map[file_count] = records_per_logSet_map
                end
            }
            logSets_per_logGroupId_map[file_count] = records_per_logSet_map
            return logSets_per_logGroupId_map,oci_la_global_metadata
            rescue => exc
                    @logger.error("Error in mapping records to oci_la_log_set.\n                                    oci_la_log_group_id: #{oci_la_log_group_id},\n                                    error message:#{exc}")
        end

        def get_zipped_stream(oci_la_log_group_id,oci_la_global_metadata,records_per_logSet_map)
          begin
            current,  = Time.now
            current_f, current_s = current.to_f, current.strftime("%Y%m%dT%H%M%S%9NZ")
            number_of_records = 0
            noOfFilesGenerated = 0
            zippedstream = Zip::OutputStream.write_buffer { |zos|
              records_per_logSet_map.each do |oci_la_log_set,records_per_logSet|
                    lrpes_for_logEvents = records_per_logSet.group_by { |event| [
                      event.get('oci_la_metadata'),
                      event.get('oci_la_entity_id'),
                      event.get('oci_la_entity_type'),
                      event.get('oci_la_log_source_name'),
                      event.get('oci_la_log_path'),
                      event.get('oci_la_timezone')
                    ]}.map { |lrpe_key, records_per_lrpe|
                      number_of_records += records_per_lrpe.length
                      LogEvents.new(lrpe_key, records_per_lrpe)
                    }
                    noOfFilesGenerated = noOfFilesGenerated +1
                    if is_valid(oci_la_log_set) then
                      nextEntry = oci_la_log_group_id+ "_#{current_s}" +"_"+ noOfFilesGenerated.to_s + "_logSet=" + oci_la_log_set + ".json"     #oci_la_log_group_id + ".json"
                      @logger.debug("Added entry #{nextEntry} for oci_la_log_set #{oci_la_log_set} into the zip.")
                    else
                      nextEntry = oci_la_log_group_id + "_#{current_s}" +"_"+ noOfFilesGenerated.to_s + ".json"
                      @logger.debug("Added entry #{nextEntry} into the zip.")
                    end
                    zos.put_next_entry(nextEntry)
                    logEventsJsonFinal = LogEventsJson.new(oci_la_global_metadata,lrpes_for_logEvents)
                    zos.write JSON.dump(logEventsJsonFinal.to_hash)
              end
            }
            zippedstream.rewind
            if @dump_zip_file
              if(!is_valid(@zip_file_location))
                @logger.error("dump_zip_file was enabled but zip_file_location was not provided.\n                                  To save zip to local you have to specify a directory.")
              end
              save_zip_to_local(oci_la_log_group_id,zippedstream,current_s)
            end
            #zippedstream.rewind if records.length > 0  #reposition buffer pointer to the beginning
            rescue => exc
              @logger.error("Error in generating payload.\n                              oci_la_log_group_id: #{oci_la_log_group_id},\n                              error message:#{exc}")
            end
          return zippedstream,number_of_records
        end

        def save_zip_to_local(oci_la_log_group_id, zippedstream, current_s)
          begin
            fileName = oci_la_log_group_id+"_"+current_s+'.zip'
            fileLocation = ::File.join(@zip_file_location, fileName)
            file = ::File.open(fileLocation, "wb")
            file.write(zippedstream.sysread)
            true
            rescue => ex
              @logger.error("Error occurred while saving zip file.\n                              oci_la_log_group_id: #{oci_la_log_group_id},\n                              fileLocation: #{@zip_file_location}\n                              fileName: #{fileName}\n                              error message: #{ex}")
              false
            ensure
              file.close unless file.nil?
          end
        end

        # returns a Metadata key and value pair for upload_log_events_file, merely descriptive
        def getCollectionSource(input)
          collections_src = []
          if !is_valid(input)
            collections_src.unshift("source:#{Source::LOGSTASH}")
          else
            if input == Source::LOGSTASH.to_s or input == Source::KUBERNETES_SOLUTION.to_s
              collections_src.unshift("source:#{input}")
            else
              # source not define ! using default source 'LOGSTASH'
              collections_src.unshift("source:#{Source::LOGSTASH}")
            end
          end
          collections_src
        end

        def is_valid(field)
          if field.nil? || field.empty? then
            return false
          else
            return true
          end
        end
      end
    end
  end
end
