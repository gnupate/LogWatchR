require 'test/unit'

require 'newlogwatchr'

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
    @time_format="%Y-%m-%d %H:%M:%S"
    @time = Time.now.strftime(@time_format)
    @mid_time =     (Time.now - 
                     10).strftime(@time_format)
    @old_time =     (Time.now - 
                     100).strftime(@time_format)
    @failing_time = (Time.now - 
                     1000).strftime(@time_format)

    # set up a DB and clear it out if needed
    @db = SQLite3::Database.new( "logwatcher.db" )
    @db.execute("drop table if exists event")
    @db.execute("create table event (
                id integer primary key, 
                host text, time text, 
                alert text, 
                alerted integer)"
                )
    @lw = WatchR.new(@db, 
                     "new_good_patterns.yml",  
                     "new_bad_patterns.yml")
  end

  def teardown
    @db.execute("drop table event")
    @db.close
  end

  def test_update_db
    @lw.update_db(@host1,@time,"test_alert",1)
    assert_equal([["1",@host1,@time,"test_alert","1"]],
                 @db.execute("select * from event"))
    @lw.update_db(@host2,@time,"test_alert",1)
    assert_equal([["1",@host1,@time,"test_alert","1"],
                 ["2",@host2,@time,"test_alert","1"]],
                 @db.execute("select * from event"))
  end

  def test_clear_db
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@old_time}', 
                '#{@alert.name}', 1)")
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@mid_time}',
                '#{@alert.name}', 1)")
    @lw.clear_db(@alert.max_age)
    assert_equal([["1",@host1,@old_time,@alert.name,"1"],
                  ["2",@host1,@mid_time,@alert.name,"1"]
                 ],
                 @db.execute("select * from event"))
    @lw.clear_db(20)
    assert_equal([["2",@host1,@mid_time,@alert.name,"1"]],
                 @db.execute("select * from event"))
    @lw.clear_db(5)
    assert_equal([],@db.execute("select * from event"))
  end



  def test_event_threshold_reached_true
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 '#{@alert.name}', 1)")
    assert(@lw.event_threshold_reached?(@host1,
                                        @alert,@time))
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
    assert(@lw.event_threshold_reached?(@host1,
                                        @alert,@time))
  end

  def test_event_threshold_reached_false_host
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@time}',
                 '#{@alert.name}', 1)")
    assert_equal(false,
                 @lw.event_threshold_reached?(@host2,
                                              @alert,
                                              @time))
  end

  def test_event_threshold_reached_false_time
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@failing_time}',
                 '#{@alert.name}', 1)")
    assert_equal(false,
                 @lw.event_threshold_reached?(@host1,
                                              @alert,
                                              @time))
  end

  def test_event_threshold_reached_false_name
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 'test_alert2', 1)")
    assert_equal(false,
                 @lw.event_threshold_reached?(@host1,
                                              @alert,
                                              @time))
  end

  def test_event_threshold_reached_false_num
    @db.execute("insert into event (
                host, time, alert, alerted)
                values ('#{@host1}', '#{@old_time}',
                'test_alert2', 1)")
    assert_equal(false,
                 @lw.event_threshold_reached?(@host1,
                                              @alert,
                                              @time))
  end

  def test_event_notified_recently_true
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 'test_alert', 1)")
    assert_equal(true,
                 @lw.event_notified_recently?(@host1,
                                             @alert,
                                             @time)) 
  end

  def test_event_notified_recently_false
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@old_time}',
                 'test_alert2', 0)")
    assert_equal(false,
                 @lw.event_notified_recently?(@host1,
                                             @alert,
                                             @time)) 
  end

  def test_event_dependencies_met_true
    @db.execute("insert into event (
                 host, time, alert, alerted)
                 values ('#{@host1}', '#{@mid_time}',
                 'test_alert2', 0)")
    assert_equal(true,
                 @lw.event_dependencies_met?(@host1,
                                             @alert,
                                             @time))
  end

  def test_event_dependencies_met_true_no_dependencies
    alert2 = Pattern.new
    assert_equal(true,
                 @lw.event_dependencies_met?("app001",
                                             alert2,
                                             @time))
  end

  def test_event_dependencies_met_false_not_present
    assert_equal(false,@lw.event_dependencies_met?(@host1, @alert, @time))
  end

  def test_event_dependencies_met_false_too_old
    # override the @alert.dependancy_max_age to
    # a failing value
    @alert.dependancy_max_age = 20

    @db.execute("insert into event (host, time, alert, alerted) values ('#{@host1}', '#{@old_time}', 'test_alert2', 0)")
    assert_equal(false,@lw.event_dependencies_met?(@host1, @alert, @time))
  end

  def test_analyze_entry_good
    test_string = "Jan 31 23:31:10 app001.app.prod.indexing.fsglobal.net Accepted publickey"
    assert(@lw.analyze_entry(test_string))
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
    @lw.update_db("app001.app.prod.indexing.fsglobal.net",
                  @mid_time,
                  "promiscuous_nic",
                  1)
    base_time = Time.now
    time = base_time.strftime("%Y-%m-%d %H:%M:%S")
    short_time = base_time.strftime("%m %d %H:%M:%S")
    test_string = "#{short_time} app001.app.prod.indexing.fsglobal.net kernel: kernel: device eth0 entered promiscuous mode"
    assert_equal(false,
                 @lw.analyze_entry(test_string))
    assert_equal([["1",
                   "app001.app.prod.indexing.fsglobal.net",
                   @mid_time,
                   "promiscuous_nic",
                   "1"],
                  ["2",
                   "app001.app.prod.indexing.fsglobal.net",
                   time,
                   "promiscuous_nic",
                   "0"]],
                 @db.execute("select * from event"))
  end

  def test_analyze_entry_bad_second_alert_but_first_is_old
    @lw.update_db("app001.app.prod.indexing.fsglobal.net",
                  @failing_time,
                  "promiscuous_nic",
                  1)
    base_time = Time.now
    time = base_time.strftime("%Y-%m-%d %H:%M:%S")
    short_time = base_time.strftime("%m %d %H:%M:%S")
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

end
