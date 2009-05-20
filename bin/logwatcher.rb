#!/usr/bin/ruby

require 'logwatchr'

watcher = WatchR.new('hosts', 'good_patterns.yml', 'bad_patterns.yml')

$stdin.each_line do |line|
  watcher.analyze_entry(line)
end

