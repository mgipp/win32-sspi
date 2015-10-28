require 'ffi'
require_relative 'constants'

class String
  # Determine if a string is base64 encoded. Use this to automatically
  # decode tokens if already encoded.
  #
  def base64?
    unpack("m").pack("m").delete("\n") == delete("\n")
  end
end

class SecurityStatusError < StandardError
  extend FFI::Library

  ffi_lib :kernel32
  attach_function :FormatMessageA, [:ulong, :ulong, :ulong, :ulong, :pointer, :ulong, :pointer], :ulong

  def initialize(context,status,errno)
    hex_status = '0x%X' % status
    msg = get_return_status_message(status)
    super("#{context}:\nffi_errno:#{errno} win32_status:#{hex_status}\nwin32 message:#{msg}")
  end

  def get_return_status_message(win32_return_status)
    buf = FFI::MemoryPointer.new(:char, 512)
    flags = 0x00001000 # means format message from system table
    FormatMessageA(flags, 0, win32_return_status, 0, buf, buf.size, nil)
    buf.read_string
  end
end
