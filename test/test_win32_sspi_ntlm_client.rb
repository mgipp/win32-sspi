########################################################################
# Tests for the Win32::SSPI::Client class.
########################################################################
require 'test-unit'
require 'win32/sspi/ntlm/client'
require 'win32/sspi/ntlm/server'

class TC_Win32_SSPI_Client < Test::Unit::TestCase
  def setup
    @client = Win32::SSPI::NTLM::Client.new
    @server = Win32::SSPI::NTLM::Server.new
    @type1 = nil
    @type3 = nil
  end

  test "username basic functionality" do
    assert_respond_to(@client, :username)
    assert_nothing_raised{ @client.username }
    assert_kind_of(String, @client.username)
  end

  test "username defaults to current user" do
    assert_equal(ENV['USERNAME'], @client.username)
  end

  test "domain basic functionality" do
    assert_respond_to(@client, :domain)
    assert_nothing_raised{ @client.domain }
    assert_kind_of(String, @client.domain)
  end

  test "domain defaults to current domain" do
    assert_equal(ENV['USERDOMAIN'], @client.domain)
  end

  test "password basic functionality" do
    assert_respond_to(@client, :password)
    assert_nothing_raised{ @client.password }
  end

  test "password is nil by default" do
    assert_nil(@client.password)
  end

  test "auth_type basic functionality" do
    assert_respond_to(@client, :auth_type)
    assert_nothing_raised{ @client.auth_type }
    assert_kind_of(String, @client.auth_type)
  end

  test "auth_type defaults to NTLM" do
    assert_equal('NTLM', @client.auth_type)
  end

  test "type_1_message basic functionality" do
    assert_respond_to(@client, :type_1_message)
    assert_nothing_raised{ @client.type_1_message }
  end

  test "type_1_message is initially nil" do
    assert_nil(@client.type_1_message)
  end

  test "type_3_message basic functionality" do
    assert_respond_to(@client, :type_3_message)
    assert_nothing_raised{ @client.type_3_message }
  end

  test "type_3_message is initially nil" do
    assert_nil(@client.type_3_message)
  end

  test "initial_token basic functionality" do
    assert_respond_to(@client, :initial_token)
  end

  test "initial_token method accepts an argument" do
    assert_nothing_raised{ @client.initial_token(true) }
  end

  test "initial_token generates and returns an expected token" do
    assert_nothing_raised{ @type1 = @client.initial_token }
    assert_kind_of(String, @type1)
    assert_true(@type1.size > 10)
  end

  test "the type_1_message accessor is set after initial_token is called" do
    @client.initial_token
    assert_not_nil(@client.type_1_message)
  end

  test "complete_authentication basic functionality" do
    assert_respond_to(@client, :complete_authentication)
  end

  test "complete_authentication accepts a type 2 message and returns a type 3 message" do
    assert_nothing_raised{ @type2 = @server.initial_token(@client.initial_token) }
    assert_nothing_raised{ @type3 = @client.complete_authentication(@type2) }
    assert_kind_of(String, @type3)
    assert_true(@type3.size > 10)
  end

  test "complete_authentication raises an error if a bogus token is passed" do
    assert_raise(Errno::EINVAL){ @client.complete_authentication('foo') }
  end
  
  test "initial_token invokes acquire_credentials_handle as expected" do
    client = Class.new(MockClient).new
    assert_nothing_raised{ client.initial_token(false) }
    args = client.retrieve_state(:acquire)
    
    assert_equal 9, args.length, "acquire_credentials_handle should have 9 arguments"
    assert_nil args[0], "unexpected psz_principal"
    assert_equal 'NTLM', args[1], "unexpected psz_package"
    assert_equal Windows::Constants::SECPKG_CRED_OUTBOUND, args[2], "unexpected f_credentialuse"
    assert_nil args[3], "unexpected pv_logonid"
    assert_kind_of Windows::Structs::SEC_WINNT_AUTH_IDENTITY, args[4], "unexpected p_authdata"
    assert_nil args[5], "unexpected p_getkeyfn"
    assert_nil args[6], "unexpected p_getkeyarg"
    assert_kind_of Windows::Structs::CredHandle, args[7], "unexpected ph_newcredentials"
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
  end
  
  test "initial_token invokes initialize_security_context as expected" do
    client = Class.new(MockClient).new
    assert_nothing_raised{ client.initial_token(false) }
    args = client.retrieve_state(:isc)
    
    assert_equal 12, args.length, "unexpected arguments"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_newcredentials"
    assert_nil args[1], "unexpected ph_context"
    assert_nil args[2], "unexpected psz_targetname"
    
    rflags = Windows::Constants::ISC_REQ_CONFIDENTIALITY | 
              Windows::Constants::ISC_REQ_REPLAY_DETECT | 
              Windows::Constants::ISC_REQ_CONNECTION
    assert_equal rflags, args[3], "unexpected f_contextreq"
    assert_equal 0, args[4], "unexpected reserved1"
    assert_equal Windows::Constants::SECURITY_NETWORK_DREP, args[5], "unexpected targetrep"
    assert_nil args[6], "unexpected p_input"
    assert_equal 0, args[7], "unexpected reserved2"
    assert_kind_of Windows::Structs::CtxtHandle, args[8], "unexpected ph_newcontext"
    assert_kind_of Windows::Structs::SecBufferDesc, args[9], "unexpected ph_newcontext"
    assert_kind_of FFI::MemoryPointer, args[10], "unexpected pf_contextattr"
    assert_kind_of Windows::Structs::TimeStamp, args[11], "unexpected pts_expiry"
  end
  
  test "complet_authentication invokes windows api as expected" do
    client = Class.new(MockClient).new
    assert_nothing_raised{ @type2 = @server.initial_token(client.initial_token(false)) }
    assert_nothing_raised{ @type3 = client.complete_authentication(@type2) }
    
    # check the initialize_security_context args
    args = client.retrieve_state(:isc)
    assert_equal 12, args.length
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_newcredentials"
    assert_kind_of Windows::Structs::CtxtHandle, args[1], "unexpected ph_context"
    assert_nil args[2], "unexpected psz_targetname"
    
    rflags = Windows::Constants::ISC_REQ_CONFIDENTIALITY | 
              Windows::Constants::ISC_REQ_REPLAY_DETECT | 
              Windows::Constants::ISC_REQ_CONNECTION
    assert_equal rflags, args[3], "unexpected f_contextreq"
    assert_equal 0, args[4], "unexpected reserved1"
    assert_equal Windows::Constants::SECURITY_NETWORK_DREP, args[5], "unexpected targetrep"
    assert_kind_of Windows::Structs::SecBufferDesc, args[6], "unexpected p_input"
    assert_equal 0, args[7], "unexpected reserved2"
    assert_kind_of Windows::Structs::CtxtHandle, args[8], "unexpected ph_newcontext"
    assert_kind_of Windows::Structs::SecBufferDesc, args[9], "unexpected ph_newcontext"
    assert_kind_of FFI::MemoryPointer, args[10], "unexpected pf_contextattr"
    assert_kind_of Windows::Structs::TimeStamp, args[11], "unexpected pts_expiry"

    # check the query_context_attributes args
    args = client.retrieve_state(:qca)
    assert_equal 3, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"
    assert_equal Windows::Constants::SECPKG_ATTR_NAMES, args[1], "unexpected ul_attribute"
    assert_kind_of Windows::Structs::SecPkgContext_Names, args[2], "unexpected p_buffer"

    # check the delete_secirity context args
    args = client.retrieve_state(:dsc)
    assert_equal 1, args.length
    assert_kind_of Windows::Structs::CtxtHandle, args[0], "unexpected ph_context"

    # check the free_credentials_handle args
    args = client.retrieve_state(:fch)
    assert_equal 1, args.length
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
  end

  def teardown
    @client = nil
    @server = nil
    @type1  = nil
    @type3  = nil
  end
end

class MockClient < Win32::SSPI::NTLM::Client
  def acquire_credentials_handle(*args)
    capture_state(:acquire, args)
    return super
  end
  
  def initialize_security_context(*args)
    capture_state(:isc, args)
    return super
  end
  
  def query_context_attributes(*args)
    capture_state(:qca,args)
    return super
  end
  
  def delete_security_context(*args)
    capture_state(:dsc,args)
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
