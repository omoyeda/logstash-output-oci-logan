## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require_relative '../../metrics/metricsLabels'
require_relative '../../enums/source'
require_relative '../../dto/logEventsJson'
require_relative '../../dto/logEvents'
require "benchmark"
require 'json'
require 'oci/errors'

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

  def initialize(namespace, dump_zip_file, loganalytics_client, collection_source, zip_file_location, plugin_retry_on_4xx, plugin_retry_on_5xx, retry_wait_on_4xx, retry_max_times_on_4xx, retry_wait_on_5xx, retry_max_times_on_5xx, logger)
    @namespace = namespace
    @@logger = logger
    @collection_source = collection_source
    @dump_zip_file = dump_zip_file
    @@loganalytics_client = loganalytics_client
    @zip_file_location = zip_file_location
    @plugin_retry_on_4xx = plugin_retry_on_4xx
    @plugin_retry_on_5xx = plugin_retry_on_5xx
    @retry_wait_on_4xx = retry_wait_on_4xx
    @retry_max_times_on_4xx = retry_max_times_on_4xx
    @retry_wait_on_5xx = retry_wait_on_5xx
    @retry_max_times_on_5xx = retry_max_times_on_5xx
    @metricsLabels_array = []
    @logGroup_metrics_map = Hash.new
  end
  
  # upload zipped stream to oci
  def upload_to_oci(oci_la_log_group_id, number_of_records, zippedstream, metricsLabels_array)
    tries = 0
    begin
      if tries > 0
        @@logger.info {"Retrying..."}
      end
      collection_src_prop = getCollectionSource(@collection_source)
      error_reason = nil
      error_code = nil
      opts = { payload_type: "ZIP", opc_meta_properties: collection_src_prop, retry_config:nil}

      if tries > 0
        @@logger.info {"Obtaining response..."}
      end
      
      response = @@loganalytics_client.upload_log_events_file(namespace_name=@namespace,
                                      logGroupId=oci_la_log_group_id ,
                                      uploadLogEventsFileDetails=zippedstream,
                                      opts)
      
      # @@logger.warn {" --- Retrying to upload the payload TEST --- "}
      # sleep @retry_wait_on_5xx
      # @@logger.info {"Wait time OVER - Uploading again"}
      # response = @@loganalytics_client.upload_log_events_file(namespace_name=@namespace,
      #                                 logGroupId=oci_la_log_group_id ,
      #                                 uploadLogEventsFileDetails=zippedstream,
      #                                 opts)
      # @@logger.info {"DONE --- !!!"}

      if !response.nil?  && response.status == 200 then
        headers = response.headers
        # if metricsLabels_array != nil
        #     metricsLabels_array.each { |metricsLabels|
        #       @@prometheusMetrics.records_posted.set(metricsLabels.records_valid, labels: { worker_id: metricsLabels.worker_id,
        #                                                                             tag: metricsLabels.tag,
        #                                                                             oci_la_log_group_id: metricsLabels.logGroupId,
        #                                                                             oci_la_log_source_name: metricsLabels.logSourceName,
        #                                                                             oci_la_log_set: metricsLabels.logSet})
        #     }
        # end

        @@logger.info {"The payload has been successfully uploaded to logAnalytics -
                        oci_la_log_group_id: #{oci_la_log_group_id},
                        ConsumedRecords: #{number_of_records},
                        Date: #{headers['date']},
                        Time: #{headers['timecreated']},
                        opc-request-id: #{headers['opc-request-id']},
                        opc-object-id: #{headers['opc-object-id']}"}
      end
    rescue OCI::Errors::ServiceError => serviceError
      error_code = serviceError.status_code
      case serviceError.status_code
        when 400
          error_reason = METRICS_SERVICE_ERROR_REASON_400
          @@logger.error {"oci upload exception : Error while uploading the payload. Invalid/Incorrect/missing Parameter - opc-request-id:#{serviceError.request_id}"}
          if @plugin_retry_on_4xx == false
            raise serviceError
          end
        when 401
          error_reason = METRICS_SERVICE_ERROR_REASON_401
          @@logger.error {"oci upload exception : Error while uploading the payload. Not Authenticated.
                          opc-request-id:#{serviceError.request_id}
                          message: #{serviceError.message}"}
          if @plugin_retry_on_4xx == false
            raise serviceError
          end
        when 404
          error_reason = METRICS_SERVICE_ERROR_REASON_404
          @@logger.error {"oci upload exception : Error while uploading the payload. Authorization failed for given oci_la_log_group_id against given Tenancy Namespace.
                          oci_la_log_group_id: #{oci_la_log_group_id}
                          Namespace: #{@namespace}
                          opc-request-id: #{serviceError.request_id}
                          message: #{serviceError.message}"}
          if @plugin_retry_on_4xx == false
            raise serviceError
          end
        when 429
          error_reason = METRICS_SERVICE_ERROR_REASON_429
          @@logger.error {"oci upload exception : Error while uploading the payload. Too Many Requests - opc-request-id:#{serviceError.request_id}"}
          raise serviceError
        when 500
          error_reason = METRICS_SERVICE_ERROR_REASON_500
          @@logger.error {"oci upload exception : Error while uploading the payload. Internal Server Error - opc-request-id:#{serviceError.request_id}"}
          if @plugin_retry_on_5xx == false
            raise serviceError
          end

        when 502
          error_reason = METRICS_SERVICE_ERROR_REASON_502
          @@logger.error {"oci upload exception : Error while uploading the payload. Bad Gateway - opc-request-id:#{serviceError.request_id}"}
          if @plugin_retry_on_5xx == false
            raise serviceError
          end

        when 503
          error_reason = METRICS_SERVICE_ERROR_REASON_503
          @@logger.error {"oci upload exception : Error while uploading the payload. Service unavailable - opc-request-id:#{serviceError.request_id}"}
          if @plugin_retry_on_5xx == false
            raise serviceError
          end

        when 504
          error_reason = METRICS_SERVICE_ERROR_REASON_504
          @@logger.error {"oci upload exception : Error while uploading the payload. Gateway Timeout - opc-request-id:#{serviceError.request_id}"}
          if @plugin_retry_on_5xx == false
            raise serviceError
          end

        when 505
          error_reason = METRICS_SERVICE_ERROR_REASON_505
          @@logger.error {"oci upload exception : Error while uploading the payload. HTTP Version Not Supported - opc-request-id:#{serviceError.request_id}"}
          if @plugin_retry_on_5xx == false
            raise serviceError
          end
        else
          error_reason = METRICS_SERVICE_ERROR_REASON_UNKNOWN
          @@logger.error {"oci upload exception : Error while uploading the payload #{serviceError.message}"}
          raise serviceError
      end
      # retry only on error codes 4XX
      if error_code.between?(400,499) && error_code != 429 && @plugin_retry_on_4xx
        if @retry_max_times_on_4xx == -1 || tries < @retry_max_times_on_4xx
          tries += 1
          attempt_info = @retry_max_times_on_4xx == -1 ? "#{tries} of UNLIMITED attempts" : "#{tries} of #{@retry_max_times_on_4xx} attempts"
          @@logger.warn {"Retrying to upload the payload: #{attempt_info}"}
          sleep @retry_wait_on_4xx
          @@logger.info {"Wait time Over"}
          retry
        # elsif tries < @retry_max_times_on_4xx
        #   tries += 1
        #   @@logger.warn {"Retrying to upload the payload: #{tries} of #{@retry_max_times_on_4xx} attempts"}
        #   sleep @retry_wait_on_4xx
        #   @@logger.info {"Wait time Over"}
        #   retry
        else
          @@logger.error {"Failed to upload the payload - : retried #{tries} times"}
        end
      end

      # retry only on error codes 5XX
      if error_code.between?(500,599) && @plugin_retry_on_5xx
        if @retry_max_times_on_5xx == -1 || tries < @retry_max_times_on_5xx
          tries += 1
          attempt_info = @retry_max_times_on_5xx == -1 ? "#{tries} of UNLIMITED attempts" : "#{tries} of #{@retry_max_times_on_5xx} attempts"
          @@logger.warn {"Retrying to upload the payload: #{attempt_info}"}
          sleep @retry_wait_on_5xx
          @@logger.info {"Wait time Over"}
          retry
        else
          @@logger.error {"Failed to upload the payload - : retried #{tries} times"}
        end
      end


      # if error_code.between?(500,599) && @plugin_retry_on_5xx
      #   if tries < @retry_max_times_on_5xx
      #     tries += 1
      #     @@logger.warn {"Retrying to upload the payload: #{tries} of #{@retry_max_times_on_5xx} attempts"}
      #     sleep @retry_wait_on_5xx
      #     @@logger.info {"Wait time Over"}
      #     retry
      #   else
      #     @@logger.error {"Failed to upload the payload - : retried #{@retry_max_times_on_5xx} times"}
      #   end
      # end

      # @@logger.warn {"Retrying to upload the payload: #{tries} of #{@retry_max_times} attempts"}
      # sleep @retry_wait
      # @@logger.info {"Wait time OVER - Reuploading"}
      # response = @@loganalytics_client.upload_log_events_file(namespace_name=@namespace,
      #                                 logGroupId=oci_la_log_group_id ,
      #                                 uploadLogEventsFileDetails=zippedstream,
      #                                 opts)
      # @@logger.info {"DONE UPLOADING"}
    rescue => ex
      error_reason = ex
      @@logger.error {"oci upload exception : Error while uploading the payload. #{ex}"}
      # ensure
      #     if error_reason != nil && metricsLabels_array != nil
      #         metricsLabels_array.each { |metricsLabels|
      #           @@prometheusMetrics.records_error.set(metricsLabels.records_valid, labels: {worker_id: metricsLabels.worker_id,
      #                                                                                 tag: metricsLabels.tag,
      #                                                                                 oci_la_log_group_id: metricsLabels.logGroupId,
      #                                                                                 oci_la_log_source_name: metricsLabels.logSourceName,
      #                                                                                 oci_la_log_set: metricsLabels.logSet,
      #                                                                                 error_code: error_code,
      #                                                                                 reason: error_reason})
      #         }
      # if tries < @retry_max_times
      #   tries += 1
      #   @@logger.warn {"Retrying to upload the payload: #{tries} of #{@retry_max_times} attempts"}
      #   sleep @retry_wait
      #   @@logger.info {"Wait time OVER - for ANY"}
      #   retry
      # else
      #   @@logger.error {"Failed to upload the payload - : retried #{@retry_max_times} times"}
      # end
    end
  end

  def setup_metrics(incoming_records_per_tag, invalid_records_per_tag, tag_metrics_set)
    valid_message_per_tag = Hash.new
    logGroup_metrics_map = Hash.new
    # metricsLabels_array = []

    incoming_records_per_tag.each do |key,value|
      dropped_messages = (invalid_records_per_tag.has_key?(key)) ? invalid_records_per_tag[key].to_i : 0
      valid_messages = value.to_i - dropped_messages
      valid_message_per_tag[key] = valid_messages

      metricsLabels = tag_metrics_set[key]
      if metricsLabels == nil
          metricsLabels = MetricsLabels.new
      end
      metricsLabels.records_valid = valid_messages
      # logGroup_metrics_map will have logGroupId as key and metricsLabels_array as value.
      # In a chunk we can have different logGroupIds but we are creating payloads based on logGroupId and that can internally have different logSourceName and tag data.
      # Using logGroup_metrics_map, for a given chunk, we can produce the metrics with proper logGroupId and its corresponding values.
      if metricsLabels.logGroupId != nil
          if @logGroup_metrics_map.has_key?(metricsLabels.logGroupId)
            @metricsLabels_array = @logGroup_metrics_map[metricsLabels.logGroupId]
          else
            @metricsLabels_array = []
          end
          @metricsLabels_array.push(metricsLabels)
          @logGroup_metrics_map[metricsLabels.logGroupId] = @metricsLabels_array
      end

      # @@prometheusMetrics.records_received.set(value.to_i, labels: { worker_id: metricsLabels.worker_id,
      #                                                                 tag: key,
      #                                                                 oci_la_log_group_id: metricsLabels.logGroupId,
      #                                                                 oci_la_log_source_name: metricsLabels.logSourceName,
      #                                                                 oci_la_log_set: metricsLabels.logSet})

      # @@prometheusMetrics.records_invalid.set(dropped_messages, labels: { worker_id: metricsLabels.worker_id,
      #                                                                       tag: key,
      #                                                                       oci_la_log_group_id: metricsLabels.logGroupId,
      #                                                                       oci_la_log_source_name: metricsLabels.logSourceName,
      #                                                                       oci_la_log_set: metricsLabels.logSet,
      #                                                                       reason: metricsLabels.invalid_reason})
      # @@prometheusMetrics.records_valid.set(valid_messages, labels: { worker_id: metricsLabels.worker_id,
      #                                                                     tag: key,
      #                                                                       oci_la_log_group_id: metricsLabels.logGroupId,
      #                                                                       oci_la_log_source_name: metricsLabels.logSourceName,
      #                                                                       oci_la_log_set: metricsLabels.logSet})

      if dropped_messages > 0
        @@logger.info {"Messages: #{value.to_i} \t Valid: #{valid_messages} \t Invalid: #{dropped_messages} \t tag:#{key}"}
      end
      @@logger.debug {"Messages: #{value.to_i} \t Valid: #{valid_messages} \t Invalid: #{dropped_messages} \t tag:#{key}"}
    end
  end

  def generate_payload(tags_per_logGroupId, lrpes_for_logGroupId)
    if lrpes_for_logGroupId != nil && lrpes_for_logGroupId.length > 0
      lrpes_for_logGroupId.each do |oci_la_log_group_id, records_per_logGroupId|
        begin
          tags = tags_per_logGroupId.key(oci_la_log_group_id)
          @@logger.info {"Generating payload with #{records_per_logGroupId.length}  records for oci_la_log_group_id: #{oci_la_log_group_id}"}
          zippedstream = nil
          oci_la_log_set = nil
          logSets_per_logGroupId_map = Hash.new

          @metricsLabels_array = @logGroup_metrics_map[oci_la_log_group_id]

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
                      upload_to_oci(oci_la_log_group_id, number_of_records, zippedstream, @metricsLabels_array)
                    end
                end
              }.real.round(3)
              # @@prometheusMetrics.chunk_time_to_upload.observe(chunk_upload_time_taken, labels: { worker_id: @@worker_id, oci_la_log_group_id: oci_la_log_group_id})
            end
        ensure
          zippedstream&.close
        end
      end
    end
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
          # record_hash = record.keys.map {|x| [x,true]}.to_h
          record_hash = event.to_hash
          if record_hash.has_key?("oci_la_global_metadata")
            # oci_la_global_metadata = record['oci_la_global_metadata']
            oci_la_global_metadata = event.get('oci_la_global_metadata')
          end
          is_oci_la_global_metadata_assigned = true
        end
        # oci_la_log_set = record['oci_la_log_set']
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
              @@logger.error {"Error in mapping records to oci_la_log_set.
                              oci_la_log_group_id: #{oci_la_log_group_id},
                              error message:#{exc}"}
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
              else
                nextEntry = oci_la_log_group_id + "_#{current_s}" +"_"+ noOfFilesGenerated.to_s + ".json"
              end
              @@logger.debug {"Added entry #{nextEntry} for oci_la_log_set #{oci_la_log_set} into the zip."}
              zos.put_next_entry(nextEntry)
              logEventsJsonFinal = LogEventsJson.new(oci_la_global_metadata,lrpes_for_logEvents)
              # zos.write Yajl.dump(logEventsJsonFinal.to_hash)
              zos.write JSON.dump(logEventsJsonFinal.to_hash)
        end
      }
      zippedstream.rewind
      if @dump_zip_file
        save_zip_to_local(oci_la_log_group_id,zippedstream,current_s)
      end
      #zippedstream.rewind if records.length > 0  #reposition buffer pointer to the beginning
      rescue => exc
        @@logger.error {"Error in generating payload.
                        oci_la_log_group_id: #{oci_la_log_group_id},
                        error message:#{exc}"}
      end
    return zippedstream,number_of_records
  end

  def save_zip_to_local(oci_la_log_group_id, zippedstream, current_s)
    begin
      fileName = oci_la_log_group_id+"_"+current_s+'.zip'
      fileLocation = @zip_file_location+fileName
      file = File.open(fileLocation, "w")
      file.write(zippedstream.sysread)
      rescue => ex
                    @@logger.error {"Error occurred while saving zip file.
                                    oci_la_log_group_id: #{oci_la_log_group_id},
                                    fileLocation: #{@zip_file_location}
                                    fileName: #{fileName}
                                    error message: #{ex}"}
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
      if input == "LogStash" or input == Source::KUBERNETES_SOLUTION.to_s
        collections_src.unshift("source:#{input}")
      else
        # source not define ! using default source 'LogStash'
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
