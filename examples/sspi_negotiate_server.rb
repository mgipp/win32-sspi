# Attempting to setup an example authenticating server
require 'webrick'
unless ENV['WIN32_SSPI_TEST']
  require 'win32-sspi'
  require 'negotiate/server'
else
  require 'win32/sspi/negotiate/server'
  puts "!!!! running with test environment !!!"
end

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
  
  def self.retrieve_server(auth_type=Win32::SSPI::API::Common::AUTH_TYPE_NEGOTIATE)
    state[:server] ||= Win32::SSPI::Negotiate::Server.new(auth_type: auth_type)
    state[:server]
  end
end


class RubySSPIServlet < WEBrick::HTTPServlet::AbstractServlet
  def initialize(server,auth_type)
    super server
    @auth_type = auth_type
  end
  
  def do_GET(req,resp)
    if req['Authorization'].nil? || req['Authorization'].empty?
      resp['www-authenticate'] = @auth_type
      resp.status = 401
      return
    end

    authenticated = false

    begin
      sspi_server = StateStore.retrieve_server(@auth_type)
      authenticated = sspi_server.http_authenticate(req['Authorization']) do |header,complete|
        resp['www-authenticate'] = header if header
        if complete
          resp.status = 200
          resp['Remote-User'] = sspi_server.username
          resp['Remote-User-Domain'] = sspi_server.domain
          resp['Content-Type'] = "text/plain"
          resp.body = "#{Time.now}: Hello #{sspi_server.username} at #{sspi_server.domain}"
        else
          resp.status = 401
        end
      end
    rescue SecurityStatusError => e
      sspi_server.free_handles
      StateStore.clear_state
      
      resp.status = 401
      resp['www-authenticate'] = @auth_type
      resp['Content-Type'] = "text/plain"
      resp.body = e.message
      puts "*** server encountered the following error ***\n #{e.message}"
      return
    end
    
    StateStore.clear_state if authenticated
  end

  def self.run(url,auth_type)
    uri = URI.parse(url)
    s = WEBrick::HTTPServer.new( :Binding=>uri.host, :Port=>uri.port)
    s.mount(uri.path, RubySSPIServlet, auth_type)
    trap("INT") { s.shutdown }
    s.start
  end
end

if $0 == __FILE__
  if ARGV.length < 1
    puts "usage: ruby sspi_negotiate_server.rb url [auth_type (Negotiate|NTLM default=Negotiate)]"
    puts "where: url = http://hostname:port/path"
    exit(0)
  end

  url = ARGV[0]
  auth_type = (2 == ARGV.length) ? ARGV[1] : Win32::SSPI::API::Common::AUTH_TYPE_NEGOTIATE
  RubySSPIServlet.run(url,auth_type)
end
