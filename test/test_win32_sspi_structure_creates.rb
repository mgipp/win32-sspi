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
  
=begin
  def test_create_credhandle
  end
  
  def test_create_ctxhandle
  end
  
  def test_create_timestamp
  end
  
  def test_create_secbuffer
  end
  
  def test_create_secbufferdesc
  end
  
  def test_create_secpkginfo
  end
  
  def test_create_secpkgcontext_names
  end
=end
end
