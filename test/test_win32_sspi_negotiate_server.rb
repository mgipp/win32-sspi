########################################################################
# Tests for the Win32::SSPI::Negotiate::Server class.
########################################################################
require 'test-unit'
require 'win32/sspi/negotiate/server'

class TC_Win32_SSPI_Negotiate_Server < Test::Unit::TestCase
  MockSpnegoToken = "123456789012345678901234567890"

  def setup
    @server = Win32::SSPI::Negotiate::Server.new
  end

  test "auth_type basic functionality" do
    assert_respond_to(@server, :auth_type)
    assert_respond_to(@server, :auth_type=)
    assert_nothing_raised{ @server.auth_type }
    assert_kind_of(String, @server.auth_type)
    assert_equal "Negotiate", @server.auth_type
    
    server = Win32::SSPI::Negotiate::Server.new(auth_type: "Kerberos")
    assert_equal "Kerberos", server.auth_type
  end

  test "token basic functionality" do
    assert_respond_to(@server, :token)
    assert_nothing_raised{ @server.token }
    assert_kind_of(String, @server.token)
    assert_equal "", @server.token
  end

  test "username and domain basic functionality" do
    assert_respond_to(@server, :username)
    assert_nothing_raised{ @server.username }
    assert_kind_of(String, @server.username)
    assert_equal "", @server.username
    assert_respond_to(@server, :domain)
    assert_nothing_raised{ @server.domain }
    assert_kind_of(String, @server.domain)
    assert_equal "", @server.domain
  end

  test "acquire_handle basic functionality" do
    assert_respond_to(@server, :acquire_handle)
    assert_equal 0, @server.method(:acquire_handle).arity
    assert_respond_to(@server, :acquire_credentials_handle)
    assert_equal 9, @server.method(:acquire_credentials_handle).arity
  end

  test "accept_context basic functionality" do
    assert_respond_to(@server, :accept_context)
    assert_equal -1, @server.method(:accept_context).arity
    assert_respond_to(@server, :accept_security_context)
    assert_equal 9, @server.method(:accept_security_context).arity
    assert_respond_to(@server, :complete_auth_token)
    assert_equal 2, @server.method(:complete_auth_token).arity
  end

  test "query_attributes basic functionality" do
    assert_respond_to(@server, :query_attributes)
    assert_equal 0, @server.method(:query_attributes).arity
    assert_respond_to(@server, :query_context_attributes)
    assert_equal 3, @server.method(:query_context_attributes).arity
    assert_respond_to(@server, :free_credentials_handle)
    assert_equal 1, @server.method(:free_credentials_handle).arity
  end

  test "authenticate_and_continue basic functionality" do
    assert_respond_to(@server, :authenticate_and_continue?)
    assert_equal 1, @server.method(:authenticate_and_continue?).arity
  end
  
  test "acquire_handle invokes windows api as expected" do
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
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
  end
  
  test "acquire_handle memoizes handle" do
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ @status = server.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status
  end
  
  test "acquire_handle raises when windows api returns failed status" do
    server = Class.new(MockNegotiateServer) do
      def acquire_credentials_handle(*args)
        capture_state(:ach, args)
        return Windows::Constants::SEC_E_SECPKG_NOT_FOUND
      end
    end.new
    assert_raises(Errno::EINVAL){ server.acquire_handle }
  end
  
  test "accept_context invokes windows api as expected" do
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ @status = server.accept_context(MockSpnegoToken) }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = server.retrieve_state(:asc)
    assert_equal 9, args.length, "unexpected args"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
    assert_nil args[1], "unexpected ph_context"
    assert_kind_of Windows::Structs::SecBufferDesc, args[2], "unexpected p_input"
    assert_equal Windows::Constants::ASC_REQ_DELEGATE, args[3], "unexpected f_contextreq"
    assert_equal Windows::Constants::SECURITY_NATIVE_DREP, args[4], "unexpected targetdatarep"
    assert_kind_of Windows::Structs::CtxtHandle, args[5], "unexpected ph_newcontext"
    assert_kind_of Windows::Structs::SecBufferDesc, args[6], "unexpected p_output"
    assert_kind_of FFI::MemoryPointer, args[7], "unexpected pf_contextattr"
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
  end
  
  test "accept_context raises when windows api returns failed status" do
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        capture_state(:asc, args)
        return Windows::Constants::SEC_E_SECPKG_NOT_FOUND
      end
    end.new
    assert_raises(Errno::EINVAL){ server.accept_context }
  end
  
  test "complet_auth invokes windows api as expected" do
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        capture_state(:asc, args)
        ptr = args[5]
        ptr.marshal_load([777,999])
        # can't really call super here because we have a fake auth token
        return Windows::Constants::SEC_I_COMPLETE_NEEDED
      end
    end.new

    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ @status=server.accept_context(MockSpnegoToken) }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = server.retrieve_state(:cat)
    assert_equal 2, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"
    assert_kind_of Windows::Structs::SecBufferDesc, args[1], "unexpected p_output"
  end
  
  test "complet_auth raises when windows api returns failed status" do
    server = Class.new(MockNegotiateServer) do
      def accept_security_context(*args)
        capture_state(:asc, args)
        ptr = args[5]
        ptr.marshal_load([777,999])
        # can't really call super here because we have a fake auth token
        return Windows::Constants::SEC_I_COMPLETE_NEEDED
      end
      def complete_auth_token(*args)
        capture_state(:cat,args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new

    assert_nothing_raised{ server.acquire_handle }
    assert_raises(Errno::EINVAL){ server.accept_context(MockSpnegoToken) }
  end
  
  test "query_attributes invokes windows api as expected" do
    server = Class.new(MockNegotiateServer).new
    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ server.accept_context(MockSpnegoToken) }
    assert_nothing_raised{ @status = server.query_attributes }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = server.retrieve_state(:qca)
    assert_equal 3, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"
    assert_equal Windows::Constants::SECPKG_ATTR_NAMES, args[1], "unexpected ul_attribute"
    assert_kind_of Windows::Structs::SecPkgContext_Names, args[2], "unexpected p_buffer"
    
    assert_equal "jimmy", server.username
    assert_equal "jes.local", server.domain
  end
  
  test "query_attributes raises when windows api returns failed status" do
    server = Class.new(MockNegotiateServer) do
      def query_context_attributes(*args)
        capture_state(:asc, args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new
    assert_raises(Errno::EINVAL){ server.query_attributes }
  end
  
  test "query_attributes raises when free_handle returns failed status" do
    server = Class.new(MockNegotiateServer) do
      def free_credentials_handle(*args)
        capture_state(:fch,args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new

    assert_nothing_raised{ server.acquire_handle }
    assert_nothing_raised{ server.accept_context(MockSpnegoToken) }
    assert_raises(Errno::EINVAL){ server.query_attributes }
  end

  def teardown
    @server = nil
  end
end

class MockNegotiateServer < Win32::SSPI::Negotiate::Server
  def acquire_credentials_handle(*args)
    capture_state(:ach, args)
    return super
  end
  
  def accept_security_context(*args)
    capture_state(:asc, args)
    ptr = args[5]
    ptr.marshal_load([777,999])
    # can't really call super here because we have a fake auth token
    return Windows::Constants::SEC_E_OK
  end
  
  def complete_auth_token(*args)
    capture_state(:cat,args)
    return Windows::Constants::SEC_E_OK
  end
  
  def query_context_attributes(*args)
    capture_state(:qca,args)
    ptr = args[2]
    ptr[:sUserName] = FFI::MemoryPointer::from_string("jes.local\\jimmy")
    return Windows::Constants::SEC_E_OK
  end
  
  def free_credentials_handle(*args)
    capture_state(:fch,args)
    return super
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
