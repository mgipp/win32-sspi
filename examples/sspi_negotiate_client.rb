require 'pp'
require 'net/http'
unless ENV['WIN32_SSPI_TEST']
  require 'win32-sspi'
  require 'negotiate/client'
else
  require 'win32/sspi/negotiate/client'
  puts "!!!! running with test environment !!!"
end

class RubySSPIClient
  def self.run(url,auth_type)
    uri = URI.parse(url)
    client = ('Negotiate' == auth_type) ? 
      Win32::SSPI::Negotiate::Client.new(spn:"HTTP/#{uri.host}") : 
      Win32::SSPI::Negotiate::Client.new(auth_type:auth_type)
    
    Net::HTTP.start(uri.host, uri.port) do |http|
      resp = nil
      client.http_authenticate do |header|
        req = Net::HTTP::Get.new(uri.path)
        req['Authorization'] = header
        resp = http.request(req)
        resp['www-authenticate']
      end
      
      puts resp.body if resp.body
    end
  end
end

if __FILE__ == $0
  if ARGV.length < 1
    puts "usage: ruby sspi_negotiate_client.rb url [auth_type (Negotiate|NTLM default=Negotiate)]"
    puts "where: url = http://hostname:port/path"
    exit(0)
  end

  url = ARGV[0]
  auth_type = (2 == ARGV.length) ? ARGV[1] : "Negotiate"
  RubySSPIClient.run(url,auth_type)
end
