########################################################################
# Tests for the Win32::SSPI::Negotiate::Client class.
########################################################################
require 'test-unit'
require 'win32/sspi/negotiate/client'

class TC_Win32_SSPI_Negotiate_Client < Test::Unit::TestCase
  SPN = "HTTP/virtual-server.gas.local"

  def setup
    @client = Win32::SSPI::Negotiate::Client.new(SPN)
  end

  def test_spn_basic_functionality
    assert_respond_to(@client, :spn)
    assert_nothing_raised{ @client.spn }
    assert_kind_of(String, @client.spn)
    assert_equal "HTTP/virtual-server.gas.local", @client.spn
  end

  def test_auth_type_basic_functionality
    assert_respond_to(@client, :auth_type)
    assert_nothing_raised{ @client.auth_type }
    assert_kind_of(String, @client.auth_type)
    assert_equal "Negotiate", @client.auth_type
    
    client = Win32::SSPI::Negotiate::Client.new(SPN, auth_type:"Kerberos")
    assert_equal "Kerberos", client.auth_type
  end

  def test_token_basic_functionality
    assert_respond_to(@client, :token)
    assert_nothing_raised{ @client.token }
    assert_kind_of(String, @client.token)
    assert_equal "", @client.token
  end

  def test_acquire_handle_basic_functionality
    assert_respond_to(@client, :acquire_handle)
    assert_equal 0, @client.method(:acquire_handle).arity
    assert_respond_to(@client, :acquire_credentials_handle)
    assert_equal 9, @client.method(:acquire_credentials_handle).arity
  end

  def test_initialize_context_basic_functionality
    assert_respond_to(@client, :initialize_context)
    assert_equal( -1, @client.method(:initialize_context).arity)
    assert_respond_to(@client, :initialize_security_context)
    assert_equal 12, @client.method(:initialize_security_context).arity
  end

  def test_authenticate_and_continue_basic_functionality
    assert_respond_to(@client, :authenticate_and_continue?)
    assert_equal 1, @client.method(:authenticate_and_continue?).arity
  end
  
  def test_status_continue_functionality
    assert @client.status_continue?(Windows::Constants::SEC_I_CONTINUE_NEEDED)
    refute @client.status_continue?(Windows::Constants::SEC_E_OK)
  end
  
  def test_acquire_handle_invokes_windows_api_as_expected
    client = Class.new(MockNegotiateClient).new(SPN)
    assert_nothing_raised{ @status = client.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = client.retrieve_state(:acquire)
    assert_equal 9, args.length, "acquire_credentials_handle should have 9 arguments"
    assert_equal SPN, args[0], "unexpected psz_principal"
    assert_equal 'Negotiate', args[1], "unexpected psz_package"
    assert_equal Windows::Constants::SECPKG_CRED_OUTBOUND, args[2], "unexpected f_credentialuse"
    assert_nil args[3], "unexpected pv_logonid"
    assert_nil args[4], "unexpected p_authdata"
    assert_nil args[5], "unexpected p_getkeyfn"
    assert_nil args[6], "unexpected p_getkeyarg"
    assert_kind_of Windows::Structs::CredHandle, args[7], "unexpected ph_newcredentials"
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
  end
  
  def test_acquire_handle_memoizes_handle
    client = Class.new(MockNegotiateClient).new(SPN)
    assert_nothing_raised{ client.acquire_handle }
    assert_nothing_raised{ @status = client.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status
  end
  
  def test_acquire_handle_raises_when_windows_api_returns_failed_status
    client = Class.new(MockNegotiateClient) do
      def acquire_credentials_handle(*args)
        capture_state(:acquire, args)
        return Windows::Constants::SEC_E_WRONG_PRINCIPAL
      end
    end.new(SPN)

    assert_raises(SecurityStatusError){ client.acquire_handle }
  end
  
  def test_initialize_context_invokes_windows_api_as_expected
    client = Class.new(MockNegotiateClient).new(SPN)
    assert_nothing_raised{ client.acquire_handle }
    assert_nothing_raised{ @status = client.initialize_context }
    assert_equal Windows::Constants::SEC_I_CONTINUE_NEEDED, @status

    args = client.retrieve_state(:isc)
    assert_equal 12, args.length, "unexpected arguments"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
    assert_nil args[1], "unexpected ph_context"
    assert_equal SPN, args[2], "unexpected psz_targetname"
    
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
  
  def test_initialize_context_raises_when_windows_api_returns_failed_status
    client = Class.new(MockNegotiateClient) do
      def initialize_security_context(*args)
        capture_state(:isc, args)
        return Windows::Constants::SEC_E_INVALID_TOKEN
      end
    end.new(SPN)

    assert_nothing_raised{ client.acquire_handle }
    assert_raises(SecurityStatusError){ client.initialize_context }
  end

  def teardown
    @client = nil
  end
end

class MockNegotiateClient < Win32::SSPI::Negotiate::Client
  def acquire_credentials_handle(*args)
    capture_state(:acquire, args)
    return super
  end
  
  def initialize_security_context(*args)
    capture_state(:isc, args)
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
