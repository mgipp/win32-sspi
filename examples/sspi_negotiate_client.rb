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
  def self.run(url)
    uri = URI.parse(url)
    client = Win32::SSPI::Negotiate::Client.new(spn:"HTTP/#{uri.host}")
    token = nil
    
    Net::HTTP.start(uri.host, uri.port) do |http|
      while client.authenticate_and_continue?(token)
        req = Net::HTTP::Get.new(uri.path)
        req['Authorization'] = client.construct_http_header(client.auth_type,client.token)
        resp = http.request(req)
        header = resp['www-authenticate']
        if header
          auth_type, token = client.de_construct_http_header(header)
        end
      end
      
      puts resp.body if resp.body
    end
  end
end

if __FILE__ == $0
  if ARGV.length < 1
    puts "usage: ruby sspi_negotiate_client.rb url"
    puts "where: url = http://hostname:port/path"
    exit(0)
  end

  RubySSPIClient.run(ARGV[0])
end
