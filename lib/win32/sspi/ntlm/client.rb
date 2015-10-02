require 'base64'
require_relative '../windows/constants'
require_relative '../windows/misc'
require_relative '../api/client'

module Win32
  module SSPI
    module NTLM
      class Client
        include Windows::Constants
        include API::Client

        attr_reader :username
        attr_reader :domain
        attr_reader :auth_type
        attr_reader :context
        attr_reader :credentials
        attr_reader :password

        # For analysis of type 1 messages. Not sure if this is useful yet.
        class MessageType1
          attr_reader :workstation
          attr_reader :domain
          attr_reader :signature

          # Breakdown based on http://davenport.sourceforge.net/ntlm.html
          def initialize(token)
            @signature = token[0,8].strip
            @type1_indicator = token[8,4]
            @flags = token[12,4]
            @domain_security_buffer = token[16,8]
            @worstation_security_buffer = token[24,8]
            @os_version_structure = token[32,8]
            @workstation = token[40,12]
            @domain = token[52..-1]
          end
        end

        # Creates a new Win32::SSPI::Client instance. The username, domain, and
        # password arguments are only used if the client is not using local
        # credentials when the call to initial_token is called.
        #
        def initialize(username = nil, domain = nil, password = nil, auth_type = 'NTLM')
          @username  = username || ENV['USERNAME'].dup
          @domain    = domain   || ENV['USERDOMAIN'].dup
          @password  = password
          @auth_type = auth_type
          @context   = create_ctxhandle
          @credentials = create_credhandle
          @context_attributes = FFI::MemoryPointer.new(:ulong)

          # These are initialized after calls to initial_token and complete_authentication
          @type_1_message = nil
          @type_3_message = nil
        end

        # Returns the token initialized after the call to initial_token. If the
        # encoded argument is true, it returns a base64 encoded token.
        #
        def type_1_message(encoded = false)
          if encoded
            Base64.encode64(@type_1_message).delete("\n")
          else
            @type_1_message
          end
        end

        # Returns the token initialized after the call to complete_authentication.
        # If the encoded argument is true, it returns a base64 encoded token.
        #
        def type_3_message(encoded = false)
          if encoded
            Base64.encode64(@type_3_message).delete("\n")
          else
            @type_3_message
          end
        end

        # Generate the type 1 message. If the local argument is true, then local
        # credentials are used. Otherwise, the username, domain and password
        # arguments passed to the constructor are used.
        #
        def initial_token(local = true)
          time_struct = create_timestamp
          auth_struct = nil

          # If local is true, obtain handle to credentials of the logged in user.
          #
          # FIXME: Causes the client to choke in the complete_authentication method.
          unless local
            if @username || @domain || @password
              auth_struct = create_sec_winnt_auth_identity(@username,@domain,@password)
            end
          end

          status = acquire_credentials_handle(
            nil,
            @auth_type,
            SECPKG_CRED_OUTBOUND,
            nil,
            auth_struct,
            nil,
            nil,
            @credentials,
            time_struct
          )

          if status != SEC_E_OK
            raise SecurityStatusError.new('AcquireCredentialsHandle', status, FFI.errno)
          end

          rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION
          expiry = create_timestamp

          sec_buf = create_secbuffer
          buffer  = create_secbufferdesc(sec_buf)

          status = initialize_security_context(
            @credentials,
            nil,
            nil,
            rflags,
            0,
            SECURITY_NETWORK_DREP,
            nil,
            0,
            @context,
            buffer,
            @context_attributes,
            expiry
          )

          if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED
            raise SecurityStatusError.new('InitializeSecurityContext', status, FFI.errno)
          else
            @type_1_message = sec_buf.to_ruby_s
          end

          @type_1_message
        end

        # Here the token is a type 2 message received from the server and,
        # assuming all goes well, returns a type 3 message.
        #
        def complete_authentication(token)
          rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION

          expiry = create_timestamp

          sec_buf_in = create_secbuffer(token)
          buf_in = create_secbufferdesc(sec_buf_in)

          sec_buf_out = create_secbuffer
          buf_out = create_secbufferdesc(sec_buf_out)

          status = initialize_security_context(
            @credentials,
            @context,
            nil,
            rflags,
            0,
            SECURITY_NETWORK_DREP,
            buf_in,
            0,
            @context,
            buf_out,
            @context_attributes,
            expiry
          )

          if status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK
            SecurityStatusError.new('InitializeSecurityContext', status, FFI.errno)
          end

          token = sec_buf_out.to_ruby_s

          ptr = create_secpkg_context_names

          status = query_context_attributes(@context, SECPKG_ATTR_NAMES, ptr)

          if status != SEC_E_OK
            raise SecurityStatusError.new('QueryContextAttributes', status, FFI.errno)
          end

          user_string = ptr.to_ruby_s

          if user_string.include?("\\")
            @domain, @username = user_string.split("\\")
          end

          if @context && delete_security_context(@context) != SEC_E_OK
            raise SecurityStatusError.new('DeleteSecurityContext', status, FFI.errno)
          end

          if @credentials && free_credentials_handle(@credentials) != SEC_E_OK
            raise SecurityStatusError.new('FreeCredentialsHandle', status, FFI.errno)
          end

          @context = nil
          @credentials = nil
          @context_attributes = nil
          @type_3_message = token

          token
        end
      end # Client
    end # NTLM
  end # SSPI
end # Win32

# Eventually delete this
if $0 == __FILE__
  #sspi = Win32::SSPI::NTLM::Client.new(nil, nil, 'NTLM')
  sspi = Win32::SSPI::NTLM::Client.new
  sspi.get_initial_token
  #p sspi.context
  #token = sspi.token
  #p token
  #p token
  #m = Win32::SSPI::MessageType1.new(token)
  #p m.domain
  #p m.workstation
  #p m.signature

  # According to http://davenport.sourceforge.net/ntlm.html
  #p token[0,8]   # NTLMSSP Sig
  #p token[8,4]   # Type 1 indicator
  #p token[12,4]  # Flags
  #p token[16,8]  # Supplied Domain buffer
  #p token[24,8]  # Supplied Workstation buffer
  #p token[32,-1] # OS Version structure
  #p token[40,12]  # Supplied Workstation data
  #p token[52..-1] # Supplied domain data
end
