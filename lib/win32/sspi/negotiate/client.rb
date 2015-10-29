require_relative '../windows/constants'
require_relative '../windows/misc'
require_relative '../api/client'

module Win32
  module SSPI
    module Negotiate
      class Client
        include Windows::Constants
        include API::Client
      
        attr_reader :spn
        attr_reader :auth_type
        attr_reader :token
      
        def initialize(options={})
          @spn = options[:spn]
          @auth_type = options[:auth_type] || "Negotiate"
          @token = nil
          @credentials_handle = nil
          @context_handle = nil
        end
        
        def http_authenticate(&block)
          perform_authenticate(block)
        end
        
        def perform_authenticate(block,with_http_header=true)
          status = acquire_handle
          if SEC_E_OK == status
            begin
              status = initialize_context(self.token)
              if SEC_I_CONTINUE_NEEDED == status
                token_from_block_result(block.call(block_arg_from_token))
              end
            end while( SEC_I_CONTINUE_NEEDED == status )
            
            # if using NTLM protocol we need to complete the final leg of the authentication
            if 'NTLM' == self.auth_type && SEC_E_OK == status
              block.call(block_arg_from_token)
            end
            
            if SEC_E_OK == status
              free_handles
            end
          end
        end
        
        def block_arg_from_token(with_http_header=true)
          with_http_header ? construct_http_header(self.auth_type,self.token) : self.token
        end
        
        def token_from_block_result(block_result,with_http_header=true)
          if block_result
            if with_http_header
              @auth_type, @token = de_construct_http_header(block_result)
            else
              @token = block_result
            end
          end
        end
        
        def acquire_handle
          return SEC_E_OK if @credentials_handle
          
          auth_data = nil
          if 'NTLM' == @auth_type
            auth_data = create_sec_winnt_auth_identity(ENV['USERNAME'],ENV['USERDOMAIN'],nil)
          end
          
          @credentials_handle = create_credhandle
          expiry = create_timestamp
        
          status = acquire_credentials_handle(
            @spn,
            @auth_type,
            SECPKG_CRED_OUTBOUND,
            nil,
            auth_data,
            nil,
            nil,
            @credentials_handle,
            expiry
          )

          if SEC_E_OK != status
            @credentials_handle = nil
            raise SecurityStatusError.new('AcquireCredentialsHandle', status, FFI.errno)
          end
          
          status
        end
      
        def initialize_context(token=nil)
          return SEC_E_OK if token.nil? && @context_handle
          
          ctx = @context_handle
          @context_handle ||= create_ctxhandle
          context_attributes = FFI::MemoryPointer.new(:ulong)

          rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION
          expiry = create_timestamp

          if token
            input_buffer   = create_secbuffer(token)
            input_buffer_desc  = create_secbufferdesc(input_buffer)
          end

          output_buffer = create_secbuffer
          output_buffer_desc  = create_secbufferdesc(output_buffer)
        
          status = initialize_security_context(
            @credentials_handle,
            ctx,
            @spn,
            rflags,
            0,
            SECURITY_NETWORK_DREP,
            (token ? input_buffer_desc : nil),
            0,
            @context_handle,
            output_buffer_desc,
            context_attributes,
            expiry
          )

          a_success = [SEC_E_OK, SEC_I_CONTINUE_NEEDED]
          if a_success.include?(status)
            @token = output_buffer.to_ruby_s
          else
            raise SecurityStatusError.new('InitializeSecurityContext', status, FFI.errno)
          end

          status
        end
        
        def free_handles
          result = free_context_and_credentials(@context_handle, @credentials_handle)
          @context_handle, @credentials_handle = [nil,nil]
          
          if SEC_E_OK != result[:status]
            raise SecurityStatusError.new(result[:name], result[:status], FFI.errno)
          end
          
          result[:status]
        end
      end
    end
  end
end
