#!/usr/bin/env ruby
#
# This code is licensed under the GPL v2, please see
# the file COPYING for more details

# add the load path to run logwatcher out of /opt/sysadmin/bin and
# /opt/sysadmin/lib
$LOAD_PATH << "/opt/sysadmin/lib"

require 'logwatchr'
require 'getoptlong'

opts = GetoptLong.new(
                      [ '--base-dir', '-d', GetoptLong::REQUIRED_ARGUMENT ],
                      [ '--bad-catalog', '-b', GetoptLong::REQUIRED_ARGUMENT ],
                      [ '--good-catalog', '-g', GetoptLong::REQUIRED_ARGUMENT ],
                      [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
                      [ '--no-loop', '-n', GetoptLong::NO_ARGUMENT ],
                      [ '--log', '-l', GetoptLong::REQUIRED_ARGUMENT ]
                      )

base_dir = "/var/logwatcher"
bad  = "bad_patterns.yml"
good = "good_patterns.yml"
log  = "watcher"
noloop = 0 

opts.each do |opt, arg|
  case opt
  when '--help'
    puts "
logwatcher <options>:
  --help, -h                       output this message
  --no-loop, -n                    don't run in a loop (for testing)
  --base-dir [dir], -d [dir]       use dir as the basedir for files
  --bad-catalog [file], -b [file]  read file for the bad patterns
  --good-catalog [file], -g [file] read file for the good patterns
  --log [file], -g [file]          read file (or fifo) for syslog entries
"
    exit 0
  when '--no-loop'
    noloop = 1
  when '--base-dir'
    base_dir = arg
  when '--good-catalog'
    good = arg
  when '--bad-catalog'
    bad = arg
  when '--log'
    log = arg
  end
end

bad  = base_dir + "/" + bad
good = base_dir + "/" + good
log  = base_dir + "/" + log
database = base_dir + "/logwatcher.db"

#
# if the good catalog or bad catalog doesn't exist,
# fail quickly
#
[good, bad].each do |file|
  begin
    fh = File.open(file)
  rescue Errno::ENOENT
    puts "#{file} doesn't exist"
    exit 1
  rescue Errno::EACCES
    puts "Can't open #{file}, bad permissions"
    exit 1
  end
  fh.close
end


#
# Make sure library and executable version numbers match 
#
Major = 2
Minor = 2
Revision = 1

Version = "#{Major}.#{Minor}.#{Revision}"
ShortVersion = "#{Major}.#{Minor}"

unless LogWatcher::ShortLibVersion == ShortVersion
  puts "library version (#{ LogWatcher::LibVersion}) doesn't match executable version (#{ Version})"
EOM
  exit 1
end

#
# create the DB if needed.
#
if ( File.exists?(database) )
  status = "previous run, using existing event table"
  db = SQLite3::Database.new(database)
  begin
    db.execute("select * from event")
  rescue SQLite3::SQLException
    db.execute("create table event (
               host text, time text, 
               alert text, 
               alerted integer)")
  end
else
  status = "starting afresh, creating event table"
  db = SQLite3::Database.new(database)
  db.execute("create table event (
             host text, time text, 
             alert text, 
             alerted integer)")
end


pid = fork {
  #
  # set up the WatchR and start doing stuff
  #
  watcher = WatchR.new(db, good, bad)
  date = Time.now.strftime(watcher.time_fmt)

  #
  # handle HUP signals from init.d scripts (or manual control)
  # All we really want to do is reread the good and bad catalogs
  #
  Signal.trap("HUP") do
    watcher.reload(good, bad)
    watcher.analyze_entry("#{date} #{`hostname`.chomp} reread logwatcher catalogs")
  end
  Signal.trap(5) do
    puts "caught SIGTRAP"
    exit
  end

  #
  # write a PID file for controlling from init.d scripts
  #
  File.open(base_dir + "/logwatcher.pid",'w') { |f| f.puts $$ }
  unless File.exists?(base_dir + "/logwatcher.pid") 
    puts "didn't write pid file, exiting"
    exit 1
  end

  watcher.analyze_entry("#{date} #{`hostname`.chomp} restarted logwatcher #{status}")

  if noloop == 1 # for testing, don't run a loop
    begin
      File.open(log,'r').each_line { |line| watcher.analyze_entry(line) }
    rescue Errno::ENOENT
      puts "#{log} doesn't exist"
      exit 1
    rescue Errno::EACCES
      puts "Can't open #{log}, bad permissions"
      exit 1
    end
  else # this is how we normally run
    while true
      begin
        File.open(log,'r').each_line { |line| watcher.analyze_entry(line) }
      rescue Errno::ENOENT
        puts "#{log} doesn't exist"
        exit 1
      rescue Errno::EACCES
        puts "Can't open #{log}, bad permissions"
        exit 1
      end
      sleep 1
    end
  end
}

Process.detach( pid )

exit 0
