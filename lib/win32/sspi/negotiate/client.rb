require_relative '../windows/constants'
require_relative '../windows/structs'
require_relative '../windows/misc'
require_relative '../api/client'

module Win32
  module SSPI
    module Negotiate
      class Client
        include Windows::Constants
        include Windows::Structs
        include API::Client
      
        attr_reader :spn
        attr_reader :auth_type
        attr_reader :token
      
        def initialize(spn,options={})
          @spn = spn
          @auth_type = options[:auth_type] || "Negotiate"
          @token = ""
        end
        
        def acquire_handle
          return SEC_E_OK if @credentials_handle
        
          @credentials_handle = CredHandle.new
          expiry = TimeStamp.new
        
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
            raise SystemCallError.new('AcquireCredentialsHandle', SecurityStatus.new(status))
          end
          
          status
        end
      
        def initialize_context(token=nil)
          ctx = @context_handle
          context = CtxtHandle.new
          context_attributes = FFI::MemoryPointer.new(:ulong)

          rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION
          expiry = TimeStamp.new

          if token
            input_buffer   = SecBuffer.new.init(token)
            input_buffer_desc  = SecBufferDesc.new.init(input_buffer)
          end

          output_buffer = SecBuffer.new.init
          output_buffer_desc  = SecBufferDesc.new.init(output_buffer)
        
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
            raise SystemCallError.new('InitializeSecurityContext', SecurityStatus.new(status))
          else
            bsize = output_buffer[:cbBuffer]
            @token = output_buffer[:pvBuffer].read_string_length(bsize)
          end
        
          @context_handle = context

          status
        end
      end
    end
  end
end
