require_relative 'common'

module Win32
  module SSPI
    module API
      module Client
        include Common

        def initialize_security_context(ph_credential,ph_context,psz_targetname,f_contextreq,reserved1,targetdatarep,p_input,reserved2,ph_newcontext,p_output,pf_contextattr,pts_expiry)
          status = InitializeSecurityContext(ph_credential,ph_context,psz_targetname,f_contextreq,reserved1,targetdatarep,p_input,reserved2,ph_newcontext,p_output,pf_contextattr,pts_expiry)
          return status
        end

      end
    end
  end
end
