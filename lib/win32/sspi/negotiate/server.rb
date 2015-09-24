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
      
        attr_reader :auth_type
        attr_reader :credentials_handle
        attr_reader :context_handle
      
        def initialize(options={})
          @auth_type = "Negotiate"
        end
      
        def acquire_handle
          return if @credentials_handle
        
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
        end
      
        def accept_context(msg=nil)
          ctx = @context_handle
          @context_handle ||= CtxtHandle.new

          inbuf   = SecBuffer.new.init(msg)
          inbuf_sec  = SecBufferDesc.new.init(inbuf)

          outbuf  = SecBuffer.new.init
          outbuf_sec = SecBufferDesc.new.init(outbuf)

          context_attributes = FFI::MemoryPointer.new(:ulong)
          expiry = TimeStamp.new

          status = accept_security_context(
            @credentials_handle,
            ctx,
            inbuf_sec,
            ASC_REQ_DELEGATE,
            SECURITY_NATIVE_DREP,
            @context_handle,
            outbuf_sec,
            context_attributes,
            expiry
          )

          if status != SEC_E_OK
            if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE
              status = complete_auth_token(@context_handle, outbuf_sec)
              if status != SEC_E_OK
                raise SystemCallError.new('CompleteAuthToken', SecurityStatus.new(status))
              end
            else
              unless status == SEC_I_CONTINUE_NEEDED
                raise SystemCallError.new('AcceptSecurityContext', SecurityStatus.new(status))
              end
            end
          end

          bsize = outbuf[:cbBuffer]
          msg = outbuf[:pvBuffer].read_string_length(bsize)

          [status,msg]
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
            domain, username = user_string.split("\\")
          end

          if @credentials_handle
            status = free_credentials_handle(@credentials_handle)
            if status != SEC_E_OK
              raise SystemCallError.new('FreeCredentialsHandle', SecurityStatus.new(status))
            end
          end

          [status,domain,username]
        end
      
      end
    end
  end
end
