# Attempting to setup an example authenticating server
require 'base64'
require 'webrick'
require 'win32/sspi/negotiate/server'

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
    state[:server] ||= Win32::SSPI::Negotiate::Server.new
    state[:server]
  end
end


class RubySSPIServlet < WEBrick::HTTPServlet::AbstractServlet
  def do_GET(req,resp)
    if req['Authorization'].nil? || req['Authorization'].empty?
      resp['www-authenticate'] = 'Negotiate'
      resp.status = 401
      return
    end
    
    # since a new instance of the server is created for each request
    sspi_server = StateStore.retrieve_server
    sspi_server.acquire_handle

    auth_type, token = req['Authorization'].split(" ")
    token = Base64.strict_decode64(token)
    status, token = sspi_server.accept_context(token)
  
    if sspi_server.status_continue?(status)
      token = Base64.strict_encode64(token)
      resp['www-authenticate'] = "#{auth_type} #{token}"
      resp.status = 401
      return
    end
    
    status, domain, username = sspi_server.query_attributes
    resp['Remote-User'] = username
    resp['Remote-User-Domain'] = domain
    resp.status = 200
    resp['Content-Type'] = "text/plain"
    resp.body = "#{Time.now}: Hello #{username} at #{domain}"
    if token && token.length > 0
      token = Base64.strict_encode64(token)
      resp['www-authenticate'] = "#{auth_type} #{token}"
    end
    
    StateStore.clear_state
  end

  def self.run(url)
    uri = URI.parse(url)
    s = WEBrick::HTTPServer.new( :Binding=>uri.host, :Port=>uri.port)
    s.mount(uri.path, RubySSPIServlet)
    trap("INT") { s.shutdown }
    s.start
  end
end

if $0 == __FILE__
  if ARGV.length < 1
    puts "usage: ruby -Ilib examples/sspi_negotiate_server.rb url"
    puts "where: url = http://hostname:port/path"
    exit(0)
  end
  
  RubySSPIServlet.run(ARGV[0])
end
