# encoding: utf-8
require "logstash/outputs/base"

# An logan output that does nothing.
class LogStash::Outputs::Logan < LogStash::Outputs::Base
  config_name "logan"

  public
  def register
  end # def register

  public
  def receive(event)
    return "Event received"
  end # def event
end # class LogStash::Outputs::Logan
