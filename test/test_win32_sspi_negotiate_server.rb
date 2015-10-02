########################################################################
# Tests for the Win32::SSPI::Negotiate::Server class.
########################################################################
require 'test-unit'
require 'win32/sspi/negotiate/server'

class TC_Win32_SSPI_Negotiate_Server < Test::Unit::TestCase
  MockSpnegoToken = "123456789012345678901234567890"
  MockCredentialHandle = [777,888]
  MockTimeStamp = [0x000000FF,0xFF000000]
  MockContextHandle = [123,987]
  MockSecBufferContent = "0123456789"*10
  ContextAttr = Windows::Constants::ISC_REQ_CONFIDENTIALITY | 
                Windows::Constants::ISC_REQ_REPLAY_DETECT | 
                Windows::Constants::ISC_REQ_CONNECTION

  def setup
    @server = Win32::SSPI::Negotiate::Server.new
  end

  def test_auth_type_basic_functionality
    assert_respond_to(@server, :auth_type)
    assert_respond_to(@server, :auth_type=)
    assert_nothing_raised{ @server.auth_type }
    assert_kind_of(String, @server.auth_type)
    assert_equal "Negotiate", @server.auth_type
    
    server = Win32::SSPI::Negotiate::Server.new(auth_type: "Kerberos")
    assert_equal "Kerberos", server.auth_type
  end

  def test_token_basic_functionality
    assert_respond_to(@server, :token)
    assert_nothing_raised{ @server.token }
    assert_kind_of(String, @server.token)
    assert_equal "", @server.token
  end

  def test_username_and_domain_basic_functionality
    assert_respond_to(@server, :username)
    assert_nothing_raised{ @server.username }
    assert_kind_of(String, @server.username)
    assert_equal "", @server.username
    assert_respond_to(@server, :domain)
    assert_nothing_raised{ @server.domain }
    assert_kind_of(String, @server.domain)
    assert_equal "", @server.domain
  end

  def test_acquire_handle_basic_functionality
    assert_respond_to(@server, :acquire_handle)
    assert_equal 0, @server.method(:acquire_handle).arity
    assert_respond_to(@server, :acquire_credentials_handle)
    assert_equal 9, @server.method(:acquire_credentials_handle).arity
  end

  def test_accept_context_basic_functionality
    assert_respond_to(@server, :accept_context)
    assert_equal( -1, @server.method(:accept_context).arity)
    assert_respond_to(@server, :accept_security_context)
    assert_equal 9, @server.method(:accept_security_context).arity
    assert_respond_to(@server, :complete_auth_token)
    assert_equal 2, @server.method(:complete_auth_token).arity
  end

  def test_query_attributes_basic_functionality
    assert_respond_to(@server, :query_attributes)
    assert_equal 0, @server.method(:query_attributes).arity
    assert_respond_to(@server, :query_context_attributes)
    assert_equal 3, @server.method(:query_context_attributes).arity
    assert_respond_to(@server, :free_credentials_handle)
    assert_equal 1, @server.method(:free_credentials_handle).arity
  end

  def test_authenticate_and_continue_basic_functionality
    assert_respond_to(@server, :authenticate_and_continue?)
    assert_equal 1, @server.method(:authenticate_and_continue?).arity
  end
  
  def test_acquire_handle_invokes_windows_api_as_expected
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ @status = server.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status
    
    # test acquire_credentials_handle
    args = server.retrieve_state(:ach)
    assert_equal 9, args.length, "unexpected args"
    assert_nil args[0], "unexpected psz_principal"
    assert_equal 'Negotiate', args[1], "unexpected psz_package"
    assert_equal Windows::Constants::SECPKG_CRED_INBOUND, args[2], "unexpected f_credentialuse"
    assert_nil args[3], "unexpected pv_logonid"
    assert_nil args[4], "unexpected p_authdata"
    assert_nil args[5], "unexpected p_getkeyfn"
    assert_nil args[6], "unexpected p_getkeyarg"
    assert_kind_of Windows::Structs::CredHandle, args[7], "unexpected ph_newcredentials"
    assert_equal MockCredentialHandle, args[7].marshal_dump
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
    assert_equal MockTimeStamp, args[8].marshal_dump
  end
  
  def test_acquire_handle_memoizes_handle
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ @status = server.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status
    assert_equal 9, server.retrieve_state(:ach).length
  end
  
  def test_acquire_handle_raises_when_windows_api_returns_failed_status
    server = Class.new(MockNegotiateServer) do
      def acquire_credentials_handle(*args)
        capture_state(:ach, args)
        return Windows::Constants::SEC_E_SECPKG_NOT_FOUND
      end
    end.new
    assert_raises(SecurityStatusError){ server.acquire_handle }
  end
  
  def test_accept_context_invokes_windows_api_as_expected
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ @status = server.accept_context(MockSpnegoToken) }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = server.retrieve_state(:asc)
    assert_equal 9, args.length, "unexpected args"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
    assert_equal MockCredentialHandle, args[0].marshal_dump
    assert_nil args[1], "unexpected ph_context"
    assert_kind_of Windows::Structs::SecBufferDesc, args[2], "unexpected p_input"
    assert_equal ContextAttr, args[3], "unexpected f_contextreq"
    assert_equal Windows::Constants::SECURITY_NATIVE_DREP, args[4], "unexpected targetdatarep"
    assert_kind_of Windows::Structs::CtxtHandle, args[5], "unexpected ph_newcontext"
    assert_equal MockContextHandle, args[5].marshal_dump
    assert_kind_of Windows::Structs::SecBufferDesc, args[6], "unexpected p_output"
    assert_equal MockSecBufferContent, server.token
    assert_kind_of FFI::MemoryPointer, args[7], "unexpected pf_contextattr"
    assert_equal ContextAttr, args[7].read_ulong
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
    assert_equal MockTimeStamp, args[8].marshal_dump
  end
  
  def test_accept_context_raises_when_windows_api_returns_failed_status
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        capture_state(:asc, args)
        return Windows::Constants::SEC_E_SECPKG_NOT_FOUND
      end
    end.new
    assert_raises(SecurityStatusError){ server.accept_context }
  end
  
  def test_complet_auth_invokes_windows_api_as_expected
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        super
        return Windows::Constants::SEC_I_COMPLETE_NEEDED
      end
    end.new

    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ @status=server.accept_context(MockSpnegoToken) }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = server.retrieve_state(:cat)
    assert_equal 2, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"
    assert_equal MockContextHandle, args[0].marshal_dump
    assert_kind_of Windows::Structs::SecBufferDesc, args[1], "unexpected p_output"
    assert_equal MockSecBufferContent, args[1].marshal_dump
  end
  
  def test_complet_auth_raises_when_windows_api_returns_failed_status
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        super
        return Windows::Constants::SEC_I_COMPLETE_NEEDED
      end
      def complete_auth_token(*args)
        capture_state(:cat,args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new

    assert_nothing_raised{ server.acquire_handle }
    assert_raises(SecurityStatusError){ server.accept_context(MockSpnegoToken) }
  end
  
  def test_query_attributes_invokes_windows_api_as_expected
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ server.accept_context(MockSpnegoToken) }
    assert_nothing_raised{ @status = server.query_attributes }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = server.retrieve_state(:qca)
    assert_equal 3, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"
    assert_equal MockContextHandle, args[0].marshal_dump
    assert_equal Windows::Constants::SECPKG_ATTR_NAMES, args[1], "unexpected ul_attribute"
    assert_kind_of Windows::Structs::SecPkgContext_Names, args[2], "unexpected p_buffer"
    
    assert_equal "jimmy", server.username
    assert_equal "jes.local", server.domain
  end
  
  def test_query_attributes_raises_when_windows_api_returns_failed_status
    server = Class.new(MockNegotiateServer) do
      def query_context_attributes(*args)
        capture_state(:asc, args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new
    assert_raises(SecurityStatusError){ server.query_attributes }
  end
  
  def test_query_attributes_raises_when_free_handle_returns_failed_status
    server = Class.new(MockNegotiateServer) do
      def free_credentials_handle(*args)
        capture_state(:fch,args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new

    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ server.accept_context(MockSpnegoToken) }
    assert_raises(SecurityStatusError){ server.query_attributes }
  end
  
  def test_authenticate_and_continue
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        super
        return Windows::Constants::SEC_I_COMPLETE_NEEDED
      end
    end.new
    counter = 0
    token = MockSpnegoToken
    while server.authenticate_and_continue?(token)
      token = server.token
      counter += 1
      fail "loop failed to complete in a reasonable iteration count" if counter > 3
    end

    ach_args = server.retrieve_state(:ach)
    refute_nil ach_args
    assert_equal 9, ach_args.length
    
    asc_args = server.retrieve_state(:asc)
    refute_nil asc_args
    assert_equal 9, asc_args.length
    
    cat_args = server.retrieve_state(:cat)
    refute_nil cat_args
    assert_equal 2, cat_args.length
    
    dsc_args = server.retrieve_state(:dsc)
    refute_nil dsc_args
    assert_equal 1, dsc_args.length
    
    fch_args = server.retrieve_state(:fch)
    refute_nil fch_args
    assert_equal 1, fch_args.length
  end

  def teardown
    @server = nil
  end
end

class MockNegotiateServer < Win32::SSPI::Negotiate::Server
  def acquire_credentials_handle(*args)
    s_args = retrieve_state(:ach) || Array.new
    s_args << args
    capture_state(:ach,s_args.flatten)
    # this api should return a credential handle in arg[7] and a timestamp in arg[8]
    args[7].marshal_load(TC_Win32_SSPI_Negotiate_Server::MockCredentialHandle)
    args[8].marshal_load(TC_Win32_SSPI_Negotiate_Server::MockTimeStamp)
    return Windows::Constants::SEC_E_OK
  end
  
  def accept_security_context(*args)
    capture_state(:asc, args)
    # this api should return a new context, p_output, context attr and timestamp
    args[5].marshal_load(TC_Win32_SSPI_Negotiate_Server::MockContextHandle)
    args[6].marshal_load(TC_Win32_SSPI_Negotiate_Server::MockSecBufferContent)
    args[7].write_ulong(TC_Win32_SSPI_Negotiate_Server::ContextAttr)
    args[8].marshal_load(TC_Win32_SSPI_Negotiate_Server::MockTimeStamp)
    return Windows::Constants::SEC_E_OK
  end
  
  def complete_auth_token(*args)
    capture_state(:cat,args)
    return Windows::Constants::SEC_E_OK
  end
  
  def query_context_attributes(*args)
    capture_state(:qca,args)
    args[2].marshal_load("jes.local\\jimmy")
    return Windows::Constants::SEC_E_OK
  end
  
  def delete_security_context(*args)
    capture_state(:dsc,args)
    return Windows::Constants::SEC_E_OK
  end
  
  def free_credentials_handle(*args)
    capture_state(:fch,args)
    return Windows::Constants::SEC_E_OK
  end
  
  def capture_state(key,value)
    self.class.capture_state(key,value)
  end
  
  def retrieve_state(key)
    self.class.retrieve_state(key)
  end
  
  def self.state
    @state ||= Hash.new
  end
  
  def self.capture_state(key,value)
    state[key] = value
  end
  
  def self.retrieve_state(key)
    state[key]
  end
  
  def self.clear_state
    state.clear
  end
end
