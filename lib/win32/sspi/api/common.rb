require 'base64'
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
        
        AUTH_TYPE_NEGOTIATE = 'Negotiate'
        AUTH_TYPE_NTLM = 'NTLM'
        
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
        
        def create_secpkg_context_names(name=nil)
          result = SecPkgContext_Names.new
          if name
            result[:sUserName] = FFI::MemoryPointer.from_string(name.dup)
          end
          result
        end
        
        def construct_http_header(auth_type, token)
          b64_token = token.nil? ? nil : Base64.strict_encode64(token)
          b64_token.nil? ? "#{auth_type}" : "#{auth_type} #{b64_token}"
        end
        
        def de_construct_http_header(block_result)
          auth_type, b64_token = block_result.header['www-authenticate'].split(' ')
          token = b64_token.nil? ? nil : Base64.strict_decode64(b64_token)
          [auth_type, token]
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
        
        def free_context_and_credentials(context,credentials)
          result = {name:'', status:SEC_E_OK, dsc_status:SEC_E_OK, fch_status:SEC_E_OK}
          status = delete_security_context(context)
          if SEC_E_OK != status
            result[:name], result[:status], result[:dsc_status] = ["DeleteSecurityContext", status, status]
          end
          
          status = free_credentials_handle(credentials)
          if SEC_E_OK != status
            result[:name], result[:status], result[:fch_status] = ["FreeCredentialsHandle", status, status]
          end

          return result
        end
        
      end
    end
  end
end
