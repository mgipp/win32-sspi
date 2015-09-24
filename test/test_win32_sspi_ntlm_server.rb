########################################################################
# Tests for the Win32::SSPI::Server class.
########################################################################
require 'test-unit'
require 'win32/sspi/ntlm/client'
require 'win32/sspi/ntlm/server'

class TC_Win32_SSPI_Server < Test::Unit::TestCase
  def setup
    @client = Win32::SSPI::NTLM::Client.new
    @server = Win32::SSPI::NTLM::Server.new
    @type1 = nil
    @type2 = nil
  end

  test "auth_type basic functionality" do
    assert_respond_to(@server, :auth_type)
    assert_nothing_raised{ @server.auth_type }
    assert_kind_of(String, @server.auth_type)
  end

  test "auth_type defaults to NTLM" do
    assert_equal('NTLM', @server.auth_type)
  end

  test "type_1_message basic functionality" do
    assert_respond_to(@server, :type_1_message)
    assert_nothing_raised{ @server.type_1_message }
  end

  test "type_1_message is initially nil" do
    assert_nil(@server.type_1_message)
  end

  test "type_2_message basic functionality" do
    assert_respond_to(@server, :type_2_message)
    assert_nothing_raised{ @server.type_2_message }
  end

  test "type_2_message is initially nil" do
    assert_nil(@server.type_2_message)
  end

  test "username basic functionality" do
    assert_respond_to(@server, :username)
    assert_nothing_raised{ @server.username }
  end

  test "username is initially nil" do
    assert_nil(@server.username)
  end

  test "domain basic functionality" do
    assert_respond_to(@server, :domain)
    assert_nothing_raised{ @server.domain }
  end

  test "domain is initially nil" do
    assert_nil(@server.domain)
  end

  test "initial_token basic functionality" do
    assert_respond_to(@server, :initial_token)
  end

  test "initial_token accepts a type 1 message and returns a type 2 message" do
    @type1 = @client.initial_token
    assert_nothing_raised{ @type2 = @server.initial_token(@type1) }
    assert_kind_of(String, @type2)
    assert_true(@type2.size > 10)
  end

  test "the type_1_message accessor is set after initial_token is called" do
    @type1 = @client.initial_token
    @server.initial_token(@type1)
    assert_not_nil(@server.type_1_message)
    assert_kind_of(String, @server.type_1_message)
  end

  test "the type_2_message accessor is set after initial_token is called" do
    @type1 = @client.initial_token
    @server.initial_token(@type1)
    assert_not_nil(@server.type_2_message)
    assert_kind_of(String, @server.type_2_message)
  end

  test "complete_authentication basic functionality" do
    assert_respond_to(@server, :complete_authentication)
  end

  test "complete_authentication accepts a type 3 message and returns a status" do
    @type1 = @client.initial_token
    @type2 = @server.initial_token(@type1)
    @type3 = @client.complete_authentication(@type2)
    result = nil

    assert_nothing_raised{ result = @server.complete_authentication(@type3) }
    assert_kind_of(Numeric, result)
  end

  test "complete_authentication raises an error if a bogus token is passed" do
    assert_raise(Errno::EINVAL){ @server.complete_authentication('foo') }
  end
  
  test "initial_token invokes windows api as expected" do
    server = Class.new(MockServer).new
    @type1 = @client.initial_token(false)
    @type2 = server.initial_token(@type1)
    
    # test acquire_credentials_handle
    args = server.retrieve_state(:ach)
    assert_equal 9, args.length, "unexpected args"
    assert_nil args[0], "unexpected psz_principal"
    assert_equal 'NTLM', args[1], "unexpected psz_package"
    assert_equal Windows::Constants::SECPKG_CRED_INBOUND, args[2], "unexpected f_credentialuse"
    assert_nil args[3], "unexpected pv_logonid"
    assert_nil args[4], "unexpected p_authdata"
    assert_nil args[5], "unexpected p_getkeyfn"
    assert_nil args[6], "unexpected p_getkeyarg"
    assert_kind_of Windows::Structs::CredHandle, args[7], "unexpected ph_newcredentials"
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
    
    # test accept security context
    args = server.retrieve_state(:asc)
    assert_equal 9, args.length, "unexpected args"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
    assert_nil args[1], "unexpected ph_context"
    assert_kind_of Windows::Structs::SecBufferDesc, args[2], "unexpected p_input"
    assert_equal Windows::Constants::ASC_REQ_CONFIDENTIALITY, args[3], "unexpected f_contextreq"
    assert_equal Windows::Constants::SECURITY_NATIVE_DREP, args[4], "unexpected targetdatarep"
    assert_kind_of Windows::Structs::CtxtHandle, args[5], "unexpected ph_newcontext"
    assert_kind_of Windows::Structs::SecBufferDesc, args[6], "unexpected p_output"
    assert_kind_of FFI::MemoryPointer, args[7], "unexpected pf_contextattr"
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
    
    # test complete auth token
    args = server.retrieve_state(:cat)
    assert_nil args, "unexpected args complete_auth_token should not be called"
  end
  
  test "capture bug in initial_token when accept_security_context returns complete needed" do
    server = Class.new(MockServer) do
      def accept_security_context(*args)
        return Windows::Constants::SEC_I_COMPLETE_NEEDED
      end
      def complete_auth_token(*args)
        return Windows::Constants::SEC_E_OK
      end
    end.new

    @type1 = @client.initial_token(false)
    assert_nothing_raised{ server.initial_token(@type1) }
  end
  
  test "complete_authentication invokes windows api as expected" do
    server = Class.new(MockServer).new
    @type1 = @client.initial_token
    @type2 = server.initial_token(@type1)
    @type3 = @client.complete_authentication(@type2)
    server.complete_authentication(@type3)

    # test accept security context
    args = server.retrieve_state(:asc)
    assert_equal 9, args.length, "unexpected args"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
    assert_kind_of Windows::Structs::CtxtHandle, args[1], "unexpected ph_context"
    assert_kind_of Windows::Structs::SecBufferDesc, args[2], "unexpected p_input"
    assert_equal Windows::Constants::ASC_REQ_CONFIDENTIALITY, args[3], "unexpected f_contextreq"
    assert_equal Windows::Constants::SECURITY_NATIVE_DREP, args[4], "unexpected targetdatarep"
    assert_kind_of Windows::Structs::CtxtHandle, args[5], "unexpected ph_newcontext"
    assert_kind_of Windows::Structs::SecBufferDesc, args[6], "unexpected p_output"
    assert_kind_of FFI::MemoryPointer, args[7], "unexpected pf_contextattr"
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"

    # test query context attributes
    args = server.retrieve_state(:qca)
    assert_equal 3, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"
    assert_equal Windows::Constants::SECPKG_ATTR_NAMES, args[1], "unexpected ul_attribute"
    assert_kind_of Windows::Structs::SecPkgContext_Names, args[2], "unexpected p_buffer"

    # check the free_credentials_handle args
    args = server.retrieve_state(:fch)
    assert_equal 1, args.length
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
  end
  

  def teardown
    @client = nil
    @server = nil
    @type1  = nil
    @type2  = nil
  end
end

class MockServer < Win32::SSPI::NTLM::Server
  def acquire_credentials_handle(*args)
    capture_state(:ach, args)
    return super
  end
  
  def accept_security_context(*args)
    capture_state(:asc, args)
    return super
  end
  
  def complete_auth_token(*args)
    capture_state(:cat,args)
    return super
  end
  
  def query_context_attributes(*args)
    capture_state(:qca,args)
    return super
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
