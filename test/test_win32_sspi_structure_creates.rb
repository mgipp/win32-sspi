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

  def test_create_secbufferdesc
    content = "test content"
    buffer = create_secbuffer(content)
    bufdesc = create_secbufferdesc(buffer)
    assert_equal FFI::Pointer.new(buffer.pointer), bufdesc[:pBuffers]
    assert_equal 1, bufdesc[:cBuffers]
    assert_equal SECBUFFER_VERSION, bufdesc[:ulVersion]
  end
  
  def test_create_secpkg_context_names
    name ="test"
    spkg_names = create_secpkg_context_names(name)
    assert_equal name, spkg_names[:sUserName].read_string
  end
  
  def test_to_ruby_s_accessors
    content = "test content"
    buffer = create_secbuffer(content)
    assert_equal content, buffer.to_ruby_s

    # FIXME: something un-intuitive about this ...
    buffer = create_secbuffer
    assert_equal TOKENBUFSIZE, buffer.to_ruby_s.length
    
    name ="test"
    spkg_names = create_secpkg_context_names(name)
    assert_equal name, spkg_names.to_ruby_s

    spkg_names = create_secpkg_context_names
    assert_nil spkg_names.to_ruby_s
  end
  
  def test_construct_de_construct_http_header
    srand(Time.now.to_i)
    tokenA = (1..40).inject([]) {|m,r| m << rand(255)}.join('')
    header = construct_http_header("Negotiate", tokenA)
    assert_equal "Negotiate", header[0,9]
    assert_match /\A\p{Print}+\Z/, header
    
    auth_type, tokenB = de_construct_http_header(header)
    assert_equal "Negotiate", auth_type
    assert_equal tokenA, tokenB
  end
end
