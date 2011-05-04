#!/usr/bin/ruby

# add the load path to run logwatcher out of /opt/sysadmin/bin and
# /opt/sysadmin/lib
$LOAD_PATH << "/opt/sysadmin/lib"

require 'logwatchr'

entries = {}
entries.default = 0
count = 0

File.open("unknown_log",'r').each_line do |line|
  entries[LogEntry.new(line).anonymize] += 1
  count += 1
end

# build a list of keys to the entry hash, sorted by the value, and
# output a list of keys and values. 
entries.keys.sort{ |key1,key2| entries[key1] <=> entries[key2] }.each { |key|
  puts "#{entries[key]} -> #{key}"
}

puts "#{count} total lines"
