# Attempting to setup an example authenticating server
require 'base64'
require 'webrick'
require 'win32/sspi/server'

# A way to store state across multiple requests
class StateStore
  def self.state
    @state ||= Hash.new
  end
  
  def self.store_state(key,value)
    state[key] = value
  end
  
  def self.retrieve_state(key)
    state[key]
  end
  
  def self.clear_state
    state.clear
  end
  
  def self.retrieve_server
    state[:server] ||= Win32::SSPI::Server.new
    state[:server]
  end
end


class RubySSPIServlet < WEBrick::HTTPServlet::AbstractServlet
  def do_GET(req,resp)
    # since a new instance of the server is created for each request
    sspi_server = StateStore.retrieve_server

    type_1_msg = StateStore.retrieve_state(:m1)
    if type_1_msg.nil?
      type_1_msg = req['Authorization'].split(' ').last
      StateStore.store_state(:m1,type_1_msg)

      puts "Received Type 1 message: #{type_1_msg}"
      puts "*" * 60
      
      msg = Base64.strict_decode64(type_1_msg)
      msg = sspi_server.initial_token(msg)
      type_2_msg = Base64.strict_encode64(msg)
      StateStore.store_state(:m2,type_2_msg)
      resp['www-authenticate'] = "NTLM #{type_2_msg}"

      puts "Generated a Type 2 message: #{type_2_msg}"
      puts "*" * 60

      return
    end
    
    type_3_msg = StateStore.retrieve_state(:m3)
    if type_3_msg.nil?
      type_3_msg = req['Authorization'].split(' ').last
      StateStore.store_state(:m3,type_3_msg)

      puts "Received Type 3 message: #{type_3_msg}"
      puts "*" * 60

      msg = Base64.strict_decode64(type_3_msg)
      sspi_server.complete_authentication(msg)
      
      resp['Content-Type'] = "text/plain"
      resp.body = "#{Time.now}: Hello #{sspi_server.username} at #{sspi_server.domain}"

      puts "User: " + sspi_server.username
      puts "Domain: " + sspi_server.domain
      puts "Server Completed"
      
      StateStore.clear_state
    end
  end

  def self.run
    s = WEBrick::HTTPServer.new( :Binding=>'localhost', :Port=>3005)
    s.mount('/test', RubySSPIServlet)
    trap("INT") { s.shutdown }
    s.start
  end
end

if $0 == __FILE__
  RubySSPIServlet.run
end
