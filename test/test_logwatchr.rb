#
# This code is licensed under the GPL v2, please see
# the file COPYING for more details

require 'test/unit'
require 'logwatchr'



module Net
  class SMTP
    # mocking SMTP so that we can test email notifiers ... 
    def self.start(host, port, &code)
      yield self
    end
    
    def self.send_message(string, subject, address)
      "email to: #{address} re: #{subject}\n#{string}"
    end
  end
end

class TestNetSMTP < Test::Unit::TestCase
  # just make sure that the SMTP mock works
  def test_start
    assert_equal("email to: address re: subject\nstring",
                 Net::SMTP.start("host", 25) { |s|
                   s.send_message("string", "subject", "address")
                 })
  end
end

class TestNotifier < Test::Unit::TestCase
  def test_notify_email_for_spencer
    notify = Notifier.new 
    # this needs to be rewritten to match the new email notifiers
    assert_equal("email to: address re: test\ntest msg", 
                 notify.email("test msg","test", "address"))
  end
end

class TestLogEntry < Test::Unit::TestCase
  def test_anonymize
    line_in = "2011-Apr-11 16:04:54 ctl001.search.refa.ft.fsglobal.net ntop[2558]:   **WARNING** packet truncated (14546->8232)"
    le = LogEntry.new(line_in)
    line_out = "ntop[D]: **WARNING** packet truncated (D->D)"
    assert_equal(line_out,le.anonymize)
  end

end

class TestPattern < Test::Unit::TestCase

  def setup
    # build a mock alert
    @alert = Pattern.new
    @alert.name = "test_alert"
    @alert.max_age = 300
    @alert.dependancy_num = 2
    @alert.dependancy_max_age = 300
    @alert.dependancy_name = "test_alert2"

    # set up the two hostnames we care about
    @host1 = "app001"
    @host2 = "app002"

    # set up the times we need for different alerts
    @time_format="%Y-%m-%e %H:%M:%S"
    @time = Time.now.strftime(@time_format).gsub(/- /,'-')
    @mid_time =     (Time.now - 
                     10).strftime(@time_format).gsub(/- /,'-')
    @old_time =     (Time.now - 
                     100).strftime(@time_format).gsub(/- /,'-')
    @in_hush_time = (Time.now - 
                     1_000).strftime(@time_format).gsub(/- /,'-')
    @failing_time = (Time.now - 
                     100_000).strftime(@time_format).gsub(/- /,'-')

    # set up entries hash for count_entry testing
    @entries = Hash.new
    @entries.default = 0


    # set up a DB and clear it out if needed
    @db = SQLite3::Database.new( "logwatcher.db" )
    @db.execute("drop table if exists event")
    @db.execute("create table event (
                id integer primary key, 
                host text, time text, 
                alert text, 
                alerted integer)"
                )

    @alert.db = @db
  end

  def teardown
    @db.execute("drop table event")
    @db.close
  end

  def test_to_catalog
    pat = Pattern.new
    pat.name = :test_pattern
    pat.pattern = /\d+/
    pat_string = "- !ruby/object:Pattern \n  name: :test_pattern\n  pattern: !ruby/regexp /\\d+/"
    assert_equal(pat_string,pat.to_catalog)
  end

  def test_dependencies_met_true
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@mid_time}',
                 'test_alert2', 0)")
    assert_equal(true,
                 @alert.dependencies_met?(@host1))
  end

  def test_dependencies_met_true_no_dependencies
    alert2 = Pattern.new
    assert_equal(true,
                 alert2.dependencies_met?(@host1))
  end

  def test_dependencies_met_false_not_present
    assert_equal(false,@alert.dependencies_met?(@host1))
  end

  def test_dependencies_met_false_too_old
    # override the @alert.dependancy_max_age to
    # a failing value
    @alert.dependancy_max_age = 20

    @db.execute("insert into event (host, time, alert, alerted) values ('#{@host1}', '#{@old_time}', 'test_alert2', 0)")
    assert_equal(false,@alert.dependencies_met?(@host1))
  end

  def test_notified_recently_true
    @alert.notification_hush_secs = 150
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 'test_alert', 1)")
    assert_equal(true,
                 @alert.notified_recently?(@host1)) 
  end

  def test_notified_recently_false
    @alert.notification_hush_secs = 60
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 'test_alert2', 1)")
    assert_equal(false,
                 @alert.notified_recently?(@host1)) 
  end



  def test_threshold_reached_true
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 '#{@alert.name}', 1)")
    assert(@alert.threshold_reached?(@host1))
  end

  def test_event_threshold_reached_true_mult
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 '#{@alert.name}', 1)")
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@mid_time}',
                 '#{@alert.name}', 1)")
    assert(@alert.threshold_reached?(@host1))
  end

  def test_event_threshold_reached_false_host
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@time}',
                 '#{@alert.name}', 1)")
    assert_equal(false,
                 @alert.threshold_reached?(@host2))
  end

  def test_threshold_reached_false_name
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 'test_alert2', 1)")
    assert_equal(false,
                 @alert.threshold_reached?(@host1))
  end

  def test_threshold_reached_false_num
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@old_time}',
                'test_alert2', 1)")
    assert_equal(false,
                 @alert.threshold_reached?(@host1))
  end

end

class TestWatchR < Test::Unit::TestCase

  def setup
    # build a mock alert
    @alert = Pattern.new
    @alert.name = "test_alert"
    @alert.max_age = 300
    @alert.dependancy_num = 2
    @alert.dependancy_max_age = 300
    @alert.dependancy_name = "test_alert2"

    # set up the two hostnames we care about
    @host1 = "app001"
    @host2 = "app002"

    # set up the times we need for different alerts
    @time_format="%Y-%b-%e %H:%M:%S"
    @time = Time.now.strftime(@time_format).gsub(/- /,'-')
    @mid_time =     (Time.now - 
                     10).strftime(@time_format).gsub(/- /,'-')
    @old_time =     (Time.now - 
                     100).strftime(@time_format).gsub(/- /,'-')
    @in_hush_time = (Time.now - 
                     1_000).strftime(@time_format).gsub(/- /,'-')
    @failing_time = (Time.now - 
                     100_000).strftime(@time_format).gsub(/- /,'-')

    # set up entries hash for count_entry testing
    @entries = Hash.new
    @entries.default = 0


    # set up a DB and clear it out if needed
    @db = SQLite3::Database.new( "logwatcher.db" )
    @db.execute("drop table if exists event")
    @db.execute("create table event (
                id integer primary key, 
                host text, time text, 
                alert text, 
                alerted integer)"
                )
    @alert.db = @db
    @lw = WatchR.new(@db, 
                     "good_patterns.yml",  
                     "test_bad_patterns.yml")
  end

  def teardown
    @db.execute("drop table event")
    @db.close
  end

  # this really is a private method and gets tested through public
  # methods of Pattern and WatchR ... when the DB handling gets
  # extracted to its own class, then it can be tested
  #
  #def test_update_db
  #  @lw.update(@host1,@time,"test_alert",1)
  #  assert_equal([["1",@host1,@time,"test_alert","1"]],
  #               @db.execute("select * from event"))
  #  @lw.update_db(@host2,@time,"test_alert",1)
  #  assert_equal([["1",@host1,@time,"test_alert","1"],
  #               ["2",@host2,@time,"test_alert","1"]],
  #               @db.execute("select * from event"))
  #end


  def test_read_line_ace_style
    ace_line = "Apr 28 18:48:56 10.33.253.10 ace002.exqint: %ACE-3-251010: Health probe failed for server 10.33.81.227 on port 8082, connection refused by server"
    fixed_line = "Apr 28 18:48:56 ace002.exqint: %ACE-3-251010: Health probe failed for server 10.33.81.227 on port 8082, connection refused by server"
    assert_equal(fixed_line,@lw.read_line(ace_line))
  end

  def test_read_line_normal
    norm_line = "Apr 28 18:50:01 app002.discussions.legacyprod.ft.fsglobal.net CRON[15117]: pam_unix(cron:session): session opened for user root by (uid=0)"
    assert_equal(norm_line,@lw.read_line(norm_line))
  end




  def test_clear_db
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@failing_time}', 
                '#{@alert.name}', 1)")
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@in_hush_time}', 
                '#{@alert.name}', 1)")
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@mid_time}',
                '#{@alert.name}', 0)")
    @lw.clear_db
    assert_equal([["2",@host1,@in_hush_time,@alert.name,"1"],
                  ["3",@host1,@mid_time,@alert.name,"0"]
                 ],
                 @db.execute("select * from event"))
    @lw.clear_db
    assert_equal([["2",@host1,@in_hush_time,@alert.name,"1"],
                  ["3",@host1,@mid_time,@alert.name,"0"]],
                 @db.execute("select * from event"))
  end

  def test_analyze_entry_good
    test_string = "Jan 31 23:31:10 app001.app.prod.indexing.fsglobal.net Accepted publickey"
    assert_equal(true, @lw.analyze_entry(test_string))
  end

  def test_analyze_entry_bad
    test_string = "Jan 31 23:31:10 app001.app.prod.indexing.fsglobal.net kernel: kernel: device eth0 entered promiscuous mode"
    assert_equal(false,
                 @lw.analyze_entry(test_string))
    
    assert_equal([["1",
                   "app001.app.prod.indexing.fsglobal.net",
                   "2011-Jan-31 23:31:10",
                   "promiscuous_nic",
                   "1"]],
                 @db.execute("select * from event"))
  end

  def test_analyze_entry_bad_second_alert
    base_time = Time.now
    time = base_time.strftime("%Y-%b-%e %H:%M:%S").gsub(/- /,'-')
    short_time = base_time.strftime("%b %e %H:%M:%S")
    @db.execute("insert into event 
                 (host, time, alert, alerted) 
                 values ('app001.app.prod.indexing.fsglobal.net',
                 '#{@mid_time}',
                  'failed_cfengine',
                  1)")
    test_string = "#{short_time} app001.app.prod.indexing.fsglobal.net Input file :cfservd.conf missing or busy"
    assert_equal(false,
                 @lw.analyze_entry(test_string))
    assert_equal([["1",
                   "app001.app.prod.indexing.fsglobal.net",
                   @mid_time,
                   "failed_cfengine",
                   "1"],
                  ["2",
                   "app001.app.prod.indexing.fsglobal.net",
                   time,
                   "failed_cfengine",
                   "0"]],
                 @db.execute("select * from event"))
  end

  def test_analyze_entry_bad_second_alert_but_first_is_old
    @db.execute("insert into event 
                 (host, time, alert, alerted) 
                 values ('app001.app.prod.indexing.fsglobal.net',
                 '#{@failing_time}',
                  'promiscuous_nic',
                  1)")
    base_time = Time.now
    time = base_time.strftime("%Y-%m-%e %H:%M:%S").gsub(/- /,'-')
    short_time = base_time.strftime("%m %e %H:%M:%S")
    test_string = "#{short_time} app001.app.prod.indexing.fsglobal.net kernel: kernel: device eth0 entered promiscuous mode"
    assert_equal(false,
                 @lw.analyze_entry(test_string))
    assert_equal([["1",
                   "app001.app.prod.indexing.fsglobal.net",
                   time,
                   "promiscuous_nic",
                   "1"]],
                 @db.execute("select * from event"))
  end


  def test_analyze_entry_not_found
    test_string = "Jan 31 23:31:10 app001.app.prod.indexing.fsglobal.net this is not an error I check for"
    assert_equal(false,
                 @lw.analyze_entry(test_string))

  end

  def test_count_entry_single_bad_entry
    base_time = Time.now
    short_time = base_time.strftime("%m %e %H:%M:%S")
    test_string = "#{short_time} app001.app.prod.indexing.fsglobal.net kernel: kernel: device eth0 entered promiscuous mode"
    @lw.count_entry(test_string, @entries)
    assert_equal(1, @entries[:promiscuous_nic])
  end

  def test_count_entry_two_bad_entries
    base_time = Time.now
    first_time = base_time.strftime("%m %e %H:%M:%S")
    second_time = (base_time - 300).strftime("%m %e %H:%M:%S")
    first_string = "#{first_time} app001.app.prod.indexing.fsglobal.net kernel: kernel: device eth0 entered promiscuous mode"
    second_string = "#{second_time} Input file Xcfservd.conf missing or busy"
    @lw.count_entry(first_string, @entries)
    @lw.count_entry(second_string, @entries)
    assert_equal(1, @entries[:promiscuous_nic])
    assert_equal(1, @entries[:failed_cfengine])
  end

  def test_count_entry_single_good_entry
    base_time = Time.now
    short_time = base_time.strftime("%m %e %H:%M:%S")
    test_string = "#{short_time} session closed for user"
    @lw.count_entry(test_string, @entries)
    assert_equal(1, @entries[:pam_unix_session_close])
  end

  def test_count_entry_two_mixed_entries
    base_time = Time.now
    first_time = base_time.strftime("%m %e %H:%M:%S")
    second_time = (base_time - 300).strftime("%m %e %H:%M:%S")
    first_string = "#{first_time} app001.app.prod.indexing.fsglobal.net kernel: kernel: device eth0 entered promiscuous mode"
    second_string = "#{second_time} session closed for user"
    @lw.count_entry(first_string, @entries)
    @lw.count_entry(second_string, @entries)
    assert_equal(1, @entries[:promiscuous_nic])
    assert_equal(1, @entries[:pam_unix_session_close])
  end

  def test_count_entry_unknown_entry
    base_time = Time.now
    short_time = base_time.strftime("%m %e %H:%M:%S")
    test_string = "#{short_time} unknown"
    @lw.count_entry(test_string, @entries)
    assert_equal(1, @entries[:unknown])
  end

end
