require_relative '../windows/constants'
require_relative '../windows/structs'
require_relative '../windows/functions'

module Win32
  module SSPI
    module API
      module Common
        include Windows::Constants
        include Windows::Structs
        include Windows::Functions
        
        def create_sec_winnt_auth_identity(username,domain,password)
          auth_struct = SEC_WINNT_AUTH_IDENTITY.new
          auth_struct[:Flags] = SEC_WINNT_AUTH_IDENTITY_ANSI

          if username
            auth_struct[:User] = FFI::MemoryPointer.from_string(username.dup)
            auth_struct[:UserLength] = username.size
          end

          if domain
            auth_struct[:Domain] = FFI::MemoryPointer.from_string(domain.dup)
            auth_struct[:DomainLength] = domain.size
          end

          if password
            auth_struct[:Password] = FFI::MemoryPointer.from_string(password.dup)
            auth_struct[:PasswordLength] = password.size
          end
          
          auth_struct
        end

        def create_credhandle(lower=nil,upper=nil)
          result = CredHandle.new
          
          if lower && upper
            result.marshal_load([lower,upper])
          end
          
          result
        end
        
        def create_ctxhandle(lower=nil,upper=nil)
          result = CtxtHandle.new
          
          if lower && upper
            result.marshal_load([lower,upper])
          end
          
          result
        end
        
        def create_timestamp(low=nil,high=nil)
          ts = TimeStamp.new
          if low && high
            ts[:dwLowDateTime] = low
            ts[:dwHighDateTime] = high
          end
          ts
        end
        
        def create_secbuffer(content=nil)
          SecBuffer.new.init(content)
        end
        
        def create_secbufferdesc(sec_buffer=nil)
          SecBufferDesc.new.init(sec_buffer)
        end
        
        def acquire_credentials_handle(psz_principal,psz_package,f_credentialuse,pv_logonid,p_authdata,p_getkeyfn,pv_getkeyarg,ph_credential,pts_expiry)
          status = AcquireCredentialsHandle(psz_principal,psz_package,f_credentialuse,pv_logonid,p_authdata,p_getkeyfn,pv_getkeyarg,ph_credential,pts_expiry)
          return status
        end
        
        def query_context_attributes(ph_context,ul_attribute,p_buffer)
          status = QueryContextAttributes(ph_context, ul_attribute, p_buffer)
          return status
        end
        
        def delete_security_context(ph_context)
          status = DeleteSecurityContext(ph_context)
          return status
        end
        
        def free_credentials_handle(ph_credential)
          status = FreeCredentialsHandle(ph_credential)
          return status
        end
        
        def status_continue?(status)
          Windows::Constants::SEC_I_CONTINUE_NEEDED == status
        end
      end
    end
  end
end
