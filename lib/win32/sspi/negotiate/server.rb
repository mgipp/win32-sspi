require_relative '../windows/constants'
require_relative '../windows/structs'
require_relative '../windows/misc'
require_relative '../api/server'

module Win32
  module SSPI
    module Negotiate
      class Server
        include Windows::Constants
        include Windows::Structs
        include API::Server
      
        attr_accessor :auth_type
        attr_reader :token
        attr_reader :username
        attr_reader :domain
      
        def initialize(options={})
          @auth_type = options[:auth_type] || "Negotiate"
          @token = ""
          @username = ''
          @domain = ''
          @credentials_handle = nil
          @context_handle = nil
        end
        
        def authenticate_and_continue?(token)
          status = acquire_handle
          if SEC_E_OK == status
            status = accept_context(token)
          end
          status_continue?(status)
        end
        
        def acquire_handle
          return SEC_E_OK if @credentials_handle
        
          @credentials_handle = CredHandle.new
          expiry = TimeStamp.new
        
          status = acquire_credentials_handle(
            nil,
            @auth_type,
            SECPKG_CRED_INBOUND,
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
      
        def accept_context(token=nil)
          ctx = @context_handle
          @context_handle ||= CtxtHandle.new

          if token
            input_buffer   = SecBuffer.new.init(token)
            input_buffer_desc  = SecBufferDesc.new.init(input_buffer)
          end
          
          rflags = ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONNECTION

          output_buffer  = SecBuffer.new.init
          output_buffer_desc = SecBufferDesc.new.init(output_buffer)

          context_attributes = FFI::MemoryPointer.new(:ulong)
          expiry = TimeStamp.new

          status = accept_security_context(
            @credentials_handle,
            ctx,
            (token ? input_buffer_desc : nil),
            rflags,
            SECURITY_NATIVE_DREP,
            @context_handle,
            output_buffer_desc,
            context_attributes,
            expiry
          )

          if status != SEC_E_OK
            if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE
              status = complete_auth_token(@context_handle, output_buffer_desc)
              if status != SEC_E_OK
                raise SystemCallError.new('CompleteAuthToken', SecurityStatus.new(status))
              end
            else
              unless status == SEC_I_CONTINUE_NEEDED
                raise SystemCallError.new('AcceptSecurityContext', SecurityStatus.new(status))
              end
            end
          end

          bsize = output_buffer[:cbBuffer]
          @token = output_buffer[:pvBuffer].read_string_length(bsize)

          status
        end

        def query_attributes
          # Finally, let's get the user and domain
          ptr = SecPkgContext_Names.new

          status = query_context_attributes(@context_handle, SECPKG_ATTR_NAMES, ptr)

          if status != SEC_E_OK
            raise SystemCallError.new('QueryContextAttributes', SecurityStatus.new(status))
          end

          user_string = ptr[:sUserName].read_string

          if user_string.include?("\\")
            @domain, @username = user_string.split("\\")
          end

          if @credentials_handle
            status = free_credentials_handle(@credentials_handle)
            if status != SEC_E_OK
              raise SystemCallError.new('FreeCredentialsHandle', SecurityStatus.new(status))
            end
          end

          status
        end
      
      end
    end
  end
end
