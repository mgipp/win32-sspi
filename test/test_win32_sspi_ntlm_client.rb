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

  def test_username_basic_functionality
    assert_respond_to(@client, :username)
    assert_nothing_raised{ @client.username }
    assert_kind_of(String, @client.username)
  end

  def test_username_defaults_to_current_user
    assert_equal(ENV['USERNAME'], @client.username)
  end

  def test_domain_basic_functionality
    assert_respond_to(@client, :domain)
    assert_nothing_raised{ @client.domain }
    assert_kind_of(String, @client.domain)
  end

  def test_domain_defaults_to_current_domain
    assert_equal(ENV['USERDOMAIN'], @client.domain)
  end

  def test_password_basic_functionality
    assert_respond_to(@client, :password)
    assert_nothing_raised{ @client.password }
  end

  def test_password_is_nil_by_default
    assert_nil(@client.password)
  end

  def test_auth_type_basic_functionality
    assert_respond_to(@client, :auth_type)
    assert_nothing_raised{ @client.auth_type }
    assert_kind_of(String, @client.auth_type)
  end

  def test_auth_type_defaults_to_NTLM
    assert_equal('NTLM', @client.auth_type)
  end

  def test_type_1_message_basic_functionality
    assert_respond_to(@client, :type_1_message)
    assert_nothing_raised{ @client.type_1_message }
  end

  def test_type_1_message_is_initially_nil
    assert_nil(@client.type_1_message)
  end

  def test_type_3_message_basic_functionality
    assert_respond_to(@client, :type_3_message)
    assert_nothing_raised{ @client.type_3_message }
  end

  def test_type_3_message_is_initially_nil
    assert_nil(@client.type_3_message)
  end

  def test_initial_token_basic_functionality
    assert_respond_to(@client, :initial_token)
  end

  def test_initial_token_method_accepts_an_argument
    assert_nothing_raised{ @client.initial_token(true) }
  end

  def test_initial_token_generates_and_returns_an_expected_token
    assert_nothing_raised{ @type1 = @client.initial_token }
    assert_kind_of(String, @type1)
    assert_true(@type1.size > 10)
  end

  def test_the_type_1_message_accessor_is_set_after_initial_token_is_called
    @client.initial_token
    assert_not_nil(@client.type_1_message)
  end

  def test_complete_authentication_basic_functionality
    assert_respond_to(@client, :complete_authentication)
  end

  def test_complete_authentication_accepts_a_type_2_message_and_returns_a_type_3_message
    assert_nothing_raised{ @type2 = @server.initial_token(@client.initial_token) }
    assert_nothing_raised{ @type3 = @client.complete_authentication(@type2) }
    assert_kind_of(String, @type3)
    assert_true(@type3.size > 10)
  end

  def test_complete_authentication_raises_an_error_if_a_bogus_token_is_passed
    assert_raise(SecurityStatusError){ @client.complete_authentication('foo') }
  end
  
  def test_initial_token_invokes_acquire_credentials_handle_as_expected
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
  
  def test_initial_token_invokes_initialize_security_context_as_expected
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
  
  def test_complet_authentication_invokes_windows_api_as_expected
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
