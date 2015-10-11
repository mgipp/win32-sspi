require 'pp'
require 'base64'
require 'net/http'
unless ENV['WIN32_SSPI_TEST']
  require 'win32-sspi'
  require 'ntlm/client'
else
  require 'win32/sspi/ntlm/client'
  puts "!!!! running with test environment !!!"
end

class RubySSPIClient
  def self.run(url)
    client = Win32::SSPI::NTLM::Client.new
    msg = client.initial_token
    type_1_msg = Base64.strict_encode64(msg)
    puts "Generated type 1 message: #{type_1_msg}"
    puts "*" * 60

    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port) do |http|
      req = Net::HTTP::Get.new(uri.path)
      req['Authorization'] = "NTLM #{type_1_msg}"
      resp = http.request(req)
      msg = resp['www-authenticate'].split(' ').last

      puts "Received type 2 message from server: #{msg}"
      puts "*" * 60
      
      type_2_msg = Base64.strict_decode64(msg)
      msg = client.complete_authentication(type_2_msg)
      type_3_msg = Base64.strict_encode64(msg)

      puts "Generated type 3 message: #{type_3_msg}"
      puts "*" * 60

      req['Authorization'] = "NTLM #{type_3_msg}"
      resp = http.request(req)

      puts "Received final response from server #{resp['www-authenticate']}"
      puts "*" * 60

      puts "Server Response:\n#{resp.body}"
    end
  end
end

if __FILE__ == $0
  if ARGV.length < 1
    puts "usage: ruby sspi_ntlm_client.rb url"
    exit(0)
  end

  RubySSPIClient.run(ARGV[0])
end
