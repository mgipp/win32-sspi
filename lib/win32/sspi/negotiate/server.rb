require_relative '../windows/constants'
require_relative '../windows/misc'
require_relative '../api/server'

module Win32
  module SSPI
    module Negotiate
      class Server
        include Windows::Constants
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
        
        def http_authenticate(header,&block)
          perform_authenticate(header,block,true)
        end
        
        def perform_authenticate(client_msg,block,is_http_header)
          authenticated = false

          status = acquire_handle
          if SEC_E_OK == status
            token_from_client_message(client_msg,is_http_header)
            status = accept_context(self.token)
            if SEC_I_CONTINUE_NEEDED == status
              block.call(block_arg_from_token(is_http_header),authenticated)
              return authenticated
            end
            
            if [SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE].include?(status)
              status = complete_authentication
            end
            
            if SEC_E_OK == status
              authenticated = true
              status = query_attributes
              if SEC_E_OK == status
                free_handles
              end
              
              block.call(block_arg_from_token(is_http_header),authenticated)
            end
          end
          
          return authenticated
        end
        
        def block_arg_from_token(is_http_header)
          block_arg = nil
          if self.token && self.token.length > 0
            block_arg = is_http_header ? construct_http_header(self.auth_type,self.token) : self.token
          end
          block_arg
        end
        
        def token_from_client_message(client_msg,is_http_header)
          if client_msg
            if is_http_header
              @auth_type, @token = de_construct_http_header(client_msg)
            else
              @token = client_msg
            end
          end
        end
        
        def acquire_handle
          return SEC_E_OK if @credentials_handle
        
          @credentials_handle = create_credhandle
          expiry = create_timestamp
        
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

          if SEC_E_OK != status
            @credentials_handle = nil
            raise SecurityStatusError.new('AcquireCredentialsHandle', status, FFI.errno)
          end
          
          status
        end
      
        def accept_context(token=nil)
          ctx = @context_handle
          @context_handle ||= create_ctxhandle

          if token
            input_buffer   = create_secbuffer(token)
            input_buffer_desc  = create_secbufferdesc(input_buffer)
          end
          
          rflags = ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONNECTION

          output_buffer  = create_secbuffer
          output_buffer_desc = create_secbufferdesc(output_buffer)

          context_attributes = FFI::MemoryPointer.new(:ulong)
          expiry = create_timestamp

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

          a_success = [SEC_E_OK, SEC_I_CONTINUE_NEEDED, SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE]
          if a_success.include?(status)
            @token = output_buffer.to_ruby_s
          else
            raise SecurityStatusError.new('AcceptSecurityContext', status, FFI.errno)
          end
          
          status
        end
        
        def complete_authentication
          status = SEC_E_OK
          
          if @token
            input_buffer = create_secbuffer(@token)
            input_buffer_desc  = create_secbufferdesc(input_buffer)
            
            status = complete_auth_token(@context_handle, input_buffer_desc)
            if SEC_E_OK != status
              raise SecurityStatusError.new('CompleteAuthToken', status, FFI.errno)
            end
          end
          
          status
        end

        def query_attributes
          # Finally, let's get the user and domain
          ptr = create_secpkg_context_names

          status = query_context_attributes(@context_handle, SECPKG_ATTR_NAMES, ptr)
          if SEC_E_OK != status
            raise SecurityStatusError.new('QueryContextAttributes', status, FFI.errno)
          end

          @username = ptr.to_ruby_s
          if @username.include?("\\")
            @domain, @username = @username.split("\\")
          end
          
          status = free_context_buffer(ptr)
          if SEC_E_OK != status
            raise SecurityStatusError.new('FreeContextBuffer', status, FFI.errno)
          end
          
          status
        end
        
        def free_handles
          result = free_context_and_credentials(@context_handle, @credentials_handle)
          @context_handle, @credentials_handle = [nil,nil]
          
          if SEC_E_OK != result[:status]
            raise SecurityStatusError.new(result[:name], result[:status], FFI.errno)
          end
          
          result[:status]
        end
      
      end
    end
  end
end
