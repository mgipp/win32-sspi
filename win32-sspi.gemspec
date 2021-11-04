require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-sspi'
  spec.summary    = 'Yet another SSPI library for Windows'
  spec.version    = '0.0.3'
  spec.authors    = ['Gary Sick', 'Daniel J. Berger']
  spec.license    = 'MIT'
  spec.email      = 'garys361@gmail.com'
  spec.platform   = Gem::Platform::CURRENT
  spec.required_ruby_version = '>=1.9'
  spec.homepage   = 'https://github.com/garysick/win32-sspi'
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') || f.include?('Notes.txt') }
  spec.test_files = Dir['test/*.rb']
  spec.require_paths = ['lib','lib/win32/sspi']

  spec.extra_rdoc_files  = ['README.md']

  spec.add_dependency('ffi', '~>1.9')
  spec.add_development_dependency('test-unit','~>3.0')
  spec.requirements << "This gem will only work in Windows Environment."

  spec.description = <<-EOF
    A SSPI library for Ruby on Windows using FFI under the hood.
    Supports NTLM and Negotiate protocols.
    See examples for usage.
  EOF
end
