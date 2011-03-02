require 'sqlite3'
require 'date'
require 'yaml'
require 'net/smtp'

db = SQLite3::Database.new( "logwatcher.db" )


class Pattern
  attr_accessor :name, :pattern, 
  :notification_type, 
  :notification_msg, :notification_target, :max_age,
  :dependancy_num, 
  :notification_hush_secs, 
  :dependancy_name, 
  :dependancy_max_age
end

class WatchR

  def initialize(db, good, bad)
    @db = db
    @time_fmt = "%Y-%m-%d %H:%M:%S"
    @max_alert_age = 0
    time = Time.now.tv_sec

    @good_patterns = open(good) { |f| YAML.load(f)}
    @bad_patterns = open(bad) { |f| YAML.load(f) }
    @bad_patterns.each do |pattern|
      if @max_alert_age < pattern.max_age
        @max_alert_age = pattern.max_age
      end
    end
  end


  def analyze_entry(logentry)
    clear_db(@max_alert_age)
    log_array = logentry.split
    @host = log_array[3]
    @log_msg = log_array[4..-1].join(" ")
    @time = Time.now.strftime("%Y") + "-" +
      log_array[0..1].join("-") + " " +
      log_array[2]

    @good_patterns.each do |alert|
      if is_event?(logentry, alert.pattern)
        return true
      end
    end

    @bad_patterns.each do |alert|
      if is_event?(logentry, alert.pattern)
        if event_notify?(@host, alert, @time)
          notify(@log_msg,
                 alert.notification_target,
                 alert.notification_type)
          notified = 1
        else
          notified = 0
        end
        update_db(@host, @time, alert.name, notified)
        return false
      end
    end

    notify_log("#{@time} unknown pattern:  #{@host} #{@log_msg}", 
               "unknown_log")

    false
  end

  def is_event?(log_msg, pattern)
    log_msg =~ pattern
  end

  def event_notify?(host, alert, time)
    if event_threshold_reached?(host, alert, time) &&
        !(event_notified_recently?(host, 
                                   alert, time)) &&
        event_dependencies_met?(host, alert, time)
      return true
    end
    false
  end

  def event_threshold_reached?(host, pattern, time)
    old_time = (Time.new - 
                pattern.max_age).strftime(@time_fmt)
    if ( @db.execute("select * from event where
                      host = '#{host}' and
                      alert = '#{pattern.name}'
                      and time > '#{old_time}'").length >=
         pattern.dependancy_num - 1 )
      true
    else
      false
    end
  end

  def event_notified_recently?(host, alert, time)
    if ( @db.execute("select * from event where 
                      host = '#{host}' and 
                      alert = '#{alert.name}' and
                      alerted = 1").length >= 1)
      true
    else
      false
    end
    
  end

  def event_dependencies_met?(host, alert, time)
    unless (alert.dependancy_name &&
            alert.dependancy_max_age)
      return true
    end
            
    name = alert.dependancy_name
    old_time = (Time.now - 
                alert.dependancy_max_age).strftime(@time_fmt)
    if ( @db.execute("select * from event where
                      host = '#{host}' and
                      alert = '#{name}' and
                      time > '#{old_time}'").length > 0 )
      true
    else
      false
    end
  end



  def update_db(host, time, alert, alerted)
    @db.execute("insert into event 
                 (host, time, alert, alerted) 
                 values ('#{host}', '#{time}',
                 '#{alert}', #{alerted})") 
  end

  def clear_db(seconds)
    old_time = (Time.now - seconds).strftime(@time_fmt)
    @db.execute("delete from event where time < '#{old_time}'")
  end

    def notify(log_msg, alert_target, alert_type)
    if alert_type == :log
      notify_log(log_msg, alert_target)
    elsif alert_type == :mail
      notify_mail(log_msg, alert_target)
    end
  end

  def notify_log(msg, target)
    open(target, 'a') {|f| f.puts msg }
  end

  def notify_mail(msg, target)
    msgstr= <<EOM
From: logwatcher@usys.org
To: #{target}
Subject: #{msg}

#{msg}
EOM
    Net::SMTP.start('localhost', 25) do |smtp|
      smtp.send_message(msgstr, 'logwatcher@usys.org', target)
    end
    notify_log("#{@time} #{msg}", "emailed_log")
  end


end
