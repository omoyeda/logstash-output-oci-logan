# frozen_string_literal: true

## Copyright (c) 2021, 2025  Oracle and/or its affiliates.
## The Universal Permissive License (UPL), Version 1.0 as shown at https://oss.oracle.com/licenses/upl/

# Container for per-tag metrics label values used by the plugin.
# rubocop:disable Naming/MethodName, Naming/VariableName
class MetricsLabels
  attr_accessor :worker_id, :tag, :logGroupId, :logSourceName, :logSet, :invalid_reason, :records_valid,
                :records_per_tag, :latency, :timezone

  def initialize
    @worker_id = nil
    @tag = nil
    @logGroupId = nil
    @logSourceName = nil
    @logSet = nil
    @invalid_reason = nil
    @records_valid = 0
    @records_per_tag = 0
    @latency = 0
    @timezone = nil
  end
end
# rubocop:enable Naming/MethodName, Naming/VariableName
