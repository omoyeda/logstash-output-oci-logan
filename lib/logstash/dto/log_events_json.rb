# frozen_string_literal: true

## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

require_relative './log_events'

# Wrapper DTO for the final OCI Log Analytics upload payload.
# rubocop:disable Naming/MethodName, Naming/MethodParameterName, Naming/VariableName
class LogEventsJson
  attr_accessor :metadata, :LogEvents

  def initialize(metadata, logEvents)
    @metadata = metadata if !metadata.nil? || metadata != 'null'
    @LogEvents = logEvents
  end

  def to_hash
    {
      metadata: @metadata,
      logEvents: @LogEvents.map(&:to_hash)
    }.compact
  end
end
# rubocop:enable Naming/MethodName, Naming/MethodParameterName, Naming/VariableName
