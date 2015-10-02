########################################################################
# Tests for the Windows::API::create_xxx methods
########################################################################
require 'test-unit'
require 'win32/sspi/api/common'

class TC_Win32_SSPI_Negotiate_Client < Test::Unit::TestCase
  include Win32::SSPI::API::Common
  
  def test_create_sec_winnt_auth_identity
    user,domain,password = %w[tom gas yadayadayada]
    identity = create_sec_winnt_auth_identity(user,domain,password)
    assert_equal user, identity[:User].read_string
    assert_equal user.length, identity[:UserLength]
    assert_equal domain, identity[:Domain].read_string
    assert_equal domain.length, identity[:DomainLength]
    assert_equal password, identity[:Password].read_string
    assert_equal password.length, identity[:PasswordLength]
    assert_equal SEC_WINNT_AUTH_IDENTITY_ANSI, identity[:Flags]
  end
  
  def test_create_credhandle
    h_credential = create_credhandle(777,888)
    assert_equal 777, h_credential[:dwLower].read_ulong
    assert_equal 888, h_credential[:dwUpper].read_ulong
    assert_equal [777,888], h_credential.marshal_dump
  end
  
  def test_create_ctxhandle
    h_ctx = create_ctxhandle(777,888)
    assert_equal 777, h_ctx[:dwLower].read_ulong
    assert_equal 888, h_ctx[:dwUpper].read_ulong
    assert_equal [777,888], h_ctx.marshal_dump
  end

  def test_create_timestamp
    ts = create_timestamp(0xFFAA8811,0x00000044)
    assert_equal 0xFFAA8811, ts[:dwLowDateTime]
    assert_equal 0x00000044, ts[:dwHighDateTime]
  end

  def test_create_secbuffer
    content = "test content"
    buffer = create_secbuffer(content)
    assert_equal content, buffer[:pvBuffer].read_string
    assert_equal content.length, buffer[:cbBuffer]
    assert_equal SECBUFFER_TOKEN, buffer[:BufferType]
    
    buffer = create_secbuffer
    assert_not_nil buffer[:pvBuffer]
    assert_equal TOKENBUFSIZE, buffer[:cbBuffer]
    assert_equal SECBUFFER_TOKEN, buffer[:BufferType]
  end
end
