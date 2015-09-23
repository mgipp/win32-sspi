require_relative '../windows/functions'

module Win32
  module SSPI
    module API
      module Client
        include Windows::Functions

        def acquire_credentials_handle(psz_principal,psz_package,f_credentialuse,pv_logonid,p_authdata,p_getkeyfn,pv_getkeyarg,ph_credential,pts_expiry)
          status = AcquireCredentialsHandle(psz_principal,psz_package,f_credentialuse,pv_logonid,p_authdata,p_getkeyfn,pv_getkeyarg,ph_credential,pts_expiry)
          return status
        end
        
        def initialize_security_context(ph_credential,ph_context,psz_targetname,f_contextreq,reserved1,targetdatarep,p_input,reserved2,ph_newcontext,p_output,pf_contextattr,pts_expiry)
          status = InitializeSecurityContext(ph_credential,ph_context,psz_targetname,f_contextreq,reserved1,targetdatarep,p_input,reserved2,ph_newcontext,p_output,pf_contextattr,pts_expiry)
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
      end
    end
  end
end
