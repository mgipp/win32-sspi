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
      
        def initialize(spn,options={})
          @spn = spn
          @auth_type = options[:auth_type] || "Negotiate"
          @token = ""
          @credentials_handle = nil
          @context_handle = nil
        end
        
        def authenticate_and_continue?(token)
          status = acquire_handle
          if SEC_E_OK == status
            status = initialize_context(token)
          end
          status_continue?(status)
        end
        
        def acquire_handle
          return SEC_E_OK if @credentials_handle
        
          @credentials_handle = create_credhandle
          expiry = create_timestamp
        
          status = acquire_credentials_handle(
            @spn,
            @auth_type,
            SECPKG_CRED_OUTBOUND,
            nil,
            nil,
            nil,
            nil,
            @credentials_handle,
            expiry
          )

          if status != SEC_E_OK
            @credentials_handle = nil
            raise SecurityStatusError.new('AcquireCredentialsHandle', status, FFI.errno)
          end
          
          status
        end
      
        def initialize_context(token=nil)
          ctx = @context_handle
          context = create_ctxhandle
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
            context,
            output_buffer_desc,
            context_attributes,
            expiry
          )

          if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED
            raise SecurityStatusError.new('InitializeSecurityContext', status, FFI.errno)
          else
            @token = output_buffer.to_ruby_s
          end
        
          @context_handle = context

          status
        end
      end
    end
  end
end
