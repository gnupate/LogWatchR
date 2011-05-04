# the WatchR class is where everything happens; log entries are
# analyzed, read, and/or anonymyzed, the catalogs are read (or
# reread); notification is done (this should be extracted); and the DB
# handles are managed (this should be extracted)
class WatchR
  attr_reader :time_fmt

  def load_yaml(catalog)
    open(catalog) { |file| YAML.load(file) }
  end

  def reload(good, bad)
    @good_patterns = load_yaml(good)
    @bad_patterns = load_yaml(bad)
    @bad_patterns.each do |pattern|
      pattern.db = @db
    end

    @max_hush = @bad_patterns.max { |first,second|
      ( first.notification_hush_secs or 0 ) <=>
      ( second.notification_hush_secs or 0 )
    }.notification_hush_secs

    @max_alert_age = @bad_patterns.max { |first,second|
      ( first.max_age or 0 ) <=> ( second.max_age or 0 )
    }.max_age
  end

  def initialize(db, good, bad)
    @db = db
    @time_fmt = "%Y-%b-%e %H:%M:%S"
    @max_alert_age = 0
    @max_hush = 86400

    self.reload(good, bad)
  end

  def read_line(logentry)
    log_array = logentry.split
    # fixme this needs to be handled more cleanly
    if log_array[4] =~ /ace00\d/
      log_array.delete_at(3)
    end 
    @host = log_array[3]
    @log_msg = log_array[3..-1].join(" ")
    @time = Time.now.strftime("%Y") + "-" +
      log_array[0..1].join("-") + " " + log_array[2]
    return log_array.join(' ')
  end

  def bad_pattern?(logentry, alert)
    # can't relocate this into Pattern until
    # notifiers is handled.
    notified = 0
    if alert.is_event?(logentry)
      if alert.notify?(@host, @time)
        notify(@log_msg,
               alert)
        notified = 1
      end
      update_db(alert, notified)
      return true
    end
  end

  def analyze_entry(logentry)
    read_line(logentry)

    @good_patterns.each do |alert|
      return true if alert.good_pattern?(logentry) 
     end

    @bad_patterns.each do |alert|
      clear_db
      return false if bad_pattern?(logentry, alert)
    end

    notify_log("#{@time} #{@log_msg}",
               # fixme this shouldn't be hard coded
               "/var/logwatcher/unknown_log")

    return false
  end

  def count_entry(logentry, entries)
    [@good_patterns, @bad_patterns].flatten.each do |alert|
      if alert.is_event?(logentry)
        entries[alert.name] += 1
        return 0
      end
    end
    entries[:unknown] += 1
  end

  def update_db(alert, alerted)
    # we should extract the db stuff to a separate DB Class.  Until
    # then, this should be treated as a private method
    @db.transaction do |db|
      db.execute("insert into event 
                 (host, time, alert, alerted) 
                 values ('#{@host}', '#{@time}',
                 '#{alert.name}', #{alerted})") 
    end
  end

  def clear_db()
    # we should extract the db stuff to a separate DB Class.
    time = Time.now
    old_time = (time - @max_alert_age).strftime(@time_fmt).gsub(/- /,'-')
    hush_time = (time - @max_hush).strftime(@time_fmt).gsub(/- /,'-')
    @db.execute("delete from event where time < '#{old_time}' and alerted = 0")
    @db.execute("delete from event where time < '#{hush_time}' and alerted = 1")
  end

  def notify(log_msg, alert)
    if alert.notification_type == :log
      notify_log(log_msg, alert.notification_target)
    elsif alert.notification_type == :mail
      notify_mail(log_msg, alert)
    end
  end

  def notify_log(msg, target)
    open(target, 'a') {|file| file.puts msg }
  end

  def notify_mail(msg, alert)
    msgstr= <<EOM
From: logwatcher@usys.org
To: #{alert.notification_target}
Subject: #{@time} #{@host} #{alert.name}

#{msg}
EOM
    Net::SMTP.start('localhost', 25) do |smtp|
      smtp.send_message(msgstr, 'logwatcher@usys.org',
                        alert.notification_target)
    end
    # fixme - this shouldn't be a hardcoded log location
    notify_log("#{@time} #{msg}", "/var/logwatcher/emailed_log")
  end

end
