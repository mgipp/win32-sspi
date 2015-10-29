require 'rake'
require 'rake/clean'
require 'rake/testtask'
require 'rubygems'
require 'rubygems/package'

CLEAN.include('**/*.gem')

namespace :gem do
  desc "Create the win32-sspi gem"
  task :create => [:clean] do
    spec = eval(IO.read('win32-sspi.gemspec'))
    Gem::Package.build(spec)
  end

  desc "Install the win32-sspi gem"
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file} -l --no-document"
  end
end

namespace :test do
  Rake::TestTask.new(:struct) do |t|
    t.test_files = FileList['test/test_win32_sspi_structure_creates.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new(:client) do |t|
    t.test_files = FileList['test/test_win32_sspi_negotiate_client.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new(:server) do |t|
    t.test_files = FileList['test/test_win32_sspi_negotiate_server.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new(:all) do |t|
    t.test_files = FileList['test/test_win32*']
    t.warning = true
    t.verbose = true
  end
end

task :default => 'test:all'
