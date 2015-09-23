require_relative '../windows/functions'

module Win32
  module SSPI
    module API
      module Server
        include Windows::Functions
        
        def acquire_credentials_handle(psz_principal,psz_package,f_credentialuse,pv_logonid,p_authdata,p_getkeyfn,pv_getkeyarg,ph_credential,pts_expiry)
          status = AcquireCredentialsHandle(psz_principal,psz_package,f_credentialuse,pv_logonid,p_authdata,p_getkeyfn,pv_getkeyarg,ph_credential,pts_expiry)
          return status
        end
        
        def accept_security_context(ph_credential,ph_context,p_input,f_contextreq,targetdatarep,ph_newcontext,p_output,pf_contextattr,pts_timestamp)
          status = AcceptSecurityContext(ph_credential,ph_context,p_input,f_contextreq,targetdatarep,ph_newcontext,p_output,pf_contextattr,pts_timestamp)
          return status
        end
        
        def complete_auth_token(ph_context,p_token)
          status = CompleteAuthToken(ph_context,p_token)
          return status
        end
        
        def query_context_attributes(ph_context,ul_attribute,p_buffer)
          status = QueryContextAttributes(ph_context, ul_attribute, p_buffer)
          return status
        end
        
        def enumerate_security_packages(pc_packages,pp_packageinfo)
          status = EnumerateSecurityPackages(pc_packages,pp_packageinfo)
          return status
        end
        
        def free_context_buffer(pv_contextbuffer)
          status = FreeContextBuffer(pv_contextbuffer)
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
      end
    end
  end
end

