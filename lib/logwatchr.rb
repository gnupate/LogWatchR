#
# This code is licensed under the GPL v2, please see
# the file COPYING for more details

require 'sqlite3'
require 'date'
require 'yaml'
require 'net/smtp'
require 'logwatchr/pattern'
require 'logwatchr/logentry'
require 'logwatchr/watchr'

module LogWatcher
  LibMajor = 2
  LibMinor = 2
  LibRevision = 1
  
  LibVersion = "#{LibMajor}.#{LibMinor}.#{LibRevision}"
  ShortLibVersion = "#{LibMajor}.#{LibMinor}"
end



