# the LogEntry class holds individual lines from the log
class LogEntry
  def initialize(line)
    @line = line
  end

  def anonymize
    @line.split()[3..-1].join(" ").gsub(/\d+/, 'D')
  end

end
