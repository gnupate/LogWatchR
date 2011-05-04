# each pattern generated from the good and bad pattern catalog
# generates a Pattern object.  These are used to test log entries,
# and to notify about them if they're events
class Pattern
  attr_accessor :db, :name, :pattern, 
  :notification_type, 
  :notification_msg, :notification_target, :max_age,
  :dependancy_num, 
  :notification_hush_secs, 
  :dependancy_name, 
  :dependancy_max_age

  def initialize
    @time_fmt = "%Y-%m-%e %H:%M:%S"
  end

  def to_catalog 
    catalog = [self].to_yaml
    carr = catalog.split(/\n/)
    carr.delete_if{ |elem| (elem =~ /time_fmt/ or elem =~ /---/) }.join("\n")
  end

  def is_event?(line)
    line =~ @pattern
  end

  def good_pattern?(logentry)
    if self.is_event?(logentry)
      return true
    end
  end

  def notify?(host, time)
    if self.dependencies_met?(host) &&
        self.threshold_reached?(host) &&
        !(self.notified_recently?(host))
      return true
    end
    return false
  end

  def dependencies_met?(host)
    unless (@dependancy_name && @dependancy_max_age)
      return true
    end
            
    old_time = (Time.now - 
                @dependancy_max_age).strftime(@time_fmt).gsub(/- /,'-')
    if ( @db.execute("select * from event where
                      host = '#{host}' and
                      alert = '#{@dependancy_name}' and
                      time > '#{old_time}'").length > 0 )
      return true
    else
      return false
    end
  end

  def threshold_reached?(host)
    old_time = (Time.new - 
                @max_age).strftime("%Y-%m-%d %H:%M:%S").gsub(/- /,'-')
    if ( @db.execute("select * from event where
                      host = '#{host}' and
                      alert = '#{@name}'
                      and time > '#{old_time}'").length >=
         @dependancy_num - 1 )
      return true
    else
      return false
    end
  end

  def notified_recently?(host)
    hush_time = (Time.now -
      @notification_hush_secs).strftime("%Y-%m-%e %H:%M:%S").gsub(/- /,'-')
    if ( @db.execute("select * from event where 
                      host = '#{host}' and 
                      alert = '#{@name}' and
                      alerted = 1 and
                      time >= '#{hush_time}'").length >= 1)
      true
    else
      false
    end
  end

end


