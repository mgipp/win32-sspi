require_relative 'common'

module Win32
  module SSPI
    module API
      module Server
        include Common
        
        def accept_security_context(ph_credential,ph_context,p_input,f_contextreq,targetdatarep,ph_newcontext,p_output,pf_contextattr,pts_timestamp)
          status = AcceptSecurityContext(ph_credential,ph_context,p_input,f_contextreq,targetdatarep,ph_newcontext,p_output,pf_contextattr,pts_timestamp)
          return status
        end
        
        def complete_auth_token(ph_context,p_token)
          status = CompleteAuthToken(ph_context,p_token)
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
      end
    end
  end
end

