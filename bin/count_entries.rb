#!/usr/bin/ruby

require 'logwatchr'

db = SQLite3::Database.new( "logwatcher.db" )

watcher = WatchR.new(db, 'good_patterns.yml', 'bad_patterns.yml')

entries = {}
entries.default = 0
File.open("equinex_test_log",'r').each_line do |line|
  watcher.count_entry(line, entries)
end


entries.keys.sort{ |key1,key2| entries[key1] <=> entries[key2] }.reverse.each { |key|
  puts "#{key} -> #{entries[key]}"
}
