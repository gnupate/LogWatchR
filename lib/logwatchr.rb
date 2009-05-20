require 'yaml'
require 'net/smtp'

 class Pattern
   attr_accessor :name, :pattern, :alert_type, :alert_msg, 
   :alert_target, :alert_last_seen_secs, :alert_last_seen_num,
   :alert_last_seen_notification_hush_secs, :alert_last_notified,
   :alert_depends_on_pattern_name, :alert_depends_on_last_seen
 end

class Event
  attr_accessor :last_seen, :last_notified, :seen_num,
  :last_seen_notification_hush_secs, :depends_on_event

  def initialize(last_seen, last_notified, last_seen_hush_secs, 
                 depends_on_event)
    @last_seen = last_seen
    @last_notified = last_notified
    @seen_num = 0
    @last_seen_notification_hush_secs = 
      last_seen_notification_hush_secs
    @depends_on_event = depends_on_event
  end
end

class WatchR
  def initialize(hosts, good, bad)
    time = Time.now.tv_sec
    @hosts = open(hosts) { |f| YAML.load(f)}
    @good_patterns = open(good) { |f| YAML.load(f)}
    @bad_patterns = open(bad) { |f| YAML.load(f)}
    @bad_patterns.each_value do |bp|
      @hosts.each_key do |host|
        build_host_alert_tree(host, bp.name)
      end
    end
  end

  def is_event?(line, pattern)
    line =~ pattern
  end

  def analyze_entry(string)
    time = Time.now
    log_array = string.split
    host = log_array[3]
    log_msg = log_array[4..-1].join(" ")

    record_host_if_unknown(host, time)

    @good_patterns.each do |alert|
      if is_event?(log_msg, alert.pattern)
        mark_host_last_seen(host, time)
        return true
      end
    end

    @bad_patterns.each_value do |alert|
      if is_event?(log_msg, alert.pattern) 
        mark_host_last_seen(host, time)

        if event_notify?(host, alert, time)
          log_msg = "#{time} #{alert.alert_msg}: #{host} #{log_msg}"
          notify(log_msg, alert.alert_target, alert.alert_type)
        end

        return false
      end
    end

    mark_host_last_seen(host, time)
    notify_log("#{time} unknown pattern:  #{host} #{log_msg}", 
               "unknown_log")
    false
  end

  def event_notify?(host, alert, time)
    if event_threshold_reached?(host, alert.name, time) &&
        !(event_notified_recently?(host, alert.name, time)) &&
        event_dependencies_met?(host, alert, time)
      return true
    end
    false
  end

  def event_dependencies_met?(host, alert, time)
    if @hosts[host][alert.name][alert.alert_depends_on_pattern_name]
      if time.tv_sec - 
          @hosts[host][alert.alert_depends_on_pattern_name][:alert_last_seen] <
          @hosts[host][alert.name][alert.alert_depends_on_pattern_last_seen]
        return true
      end
      return false 
    end
    true
  end

  def event_threshold_reached?(host, event_type, time)
    @hosts[host][event_type][:alert_last_seen].delete_if { |event_time|
      time.tv_sec - event_time > 
      @hosts[host][event_type][:alert_last_seen_secs]
    } 
    mark_alert_last_seen(event_type, host, time)

    if @hosts[host][event_type][:alert_last_seen].length >=
        @hosts[host][event_type][:alert_last_seen_num]
      true
    else
      false
    end
  end

  def event_notified_recently?(host, event_type, time)
    if ( (time.tv_sec - @hosts[host][event_type][:alert_last_notified]) <
         @hosts[host][event_type][:alert_last_seen_notification_hush_secs] )
      return true
    end
    false
  end


  def mark_host_last_seen(host, time)
    @hosts[host][:last_seen] = time.tv_sec
  end

  def mark_alert_last_seen(event_type, host, time)
    @hosts[host][event_type][:alert_last_seen] << time.tv_sec
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
    notify_log(msg, "emailed_log")
  end

  def record_host_if_unknown(host, time)
    unless @hosts.keys.include?(host)
      msg = "#{Time.now.tv_sec} #{host} logged an alert, but is unknown"
      notify_log(msg, 'unknown_hosts_log')
      @hosts[host] = Hash.new
      @hosts[host][:last_seen] = time.tv_sec
      @bad_patterns.each_value do |bp|
        build_host_alert_tree(host, bp.name)
      end
    end
  end

  def build_host_alert_tree(host, alert)
    @hosts[host][alert] = {
      :alert_last_seen => [], 
      :alert_last_notified => 0,
      :alert_last_seen_num => @bad_patterns[alert].alert_last_seen_num,
      :alert_last_seen_secs =>@bad_patterns[alert].alert_last_seen_secs,
      :alert_last_seen_notification_hush_secs =>
      @bad_patterns[alert].alert_last_seen_notification_hush_secs,
      :alert_depends_on_pattern_name =>
      @bad_patterns[alert].alert_depends_on_pattern_name,
      :alert_depends_on_last_seen => 0
    }
  end

end
