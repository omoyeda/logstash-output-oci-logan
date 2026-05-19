# frozen_string_literal: true

## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

# Payload DTO for grouped log events sent to OCI Log Analytics.
# rubocop:disable Naming/MethodName, Naming/VariableName
class LogEvents
  attr_accessor :entityId, :entityType, :logSourceName, :logPath, :logRecords, :metadata, :timezone

  def initialize(lrpe_key, logstash_records)
    @metadata, @entityId, @entityType, @logSourceName, @logPath, @timezone = lrpe_key
    @logRecords = logstash_records.map do |event|
      event.get('message')
    end
  end

  def to_hash
    {
      metadata: @metadata,
      entityId: @entityId,
      entityType: @entityType,
      logSourceName: @logSourceName,
      logPath: @logPath,
      logRecords: @logRecords,
      timezone: @timezone
    }.compact
  end
end
# rubocop:enable Naming/MethodName, Naming/VariableName
