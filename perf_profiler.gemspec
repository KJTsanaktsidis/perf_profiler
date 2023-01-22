IGNORED_EXTS = %w[.o .so]

Gem::Specification.new do |s|
  s.name        = "perf_profiler"
  s.version     = "0.0.1"
  s.summary     = "A sampling profiler for ruby using Linux's perf_events framework"
  s.authors     = ["KJ Tsanaktsidis"]
  s.email       = "kj@kjtsanaktsidis.id.au"
  s.license     = "Apache-2.0"
  s.homepage    = "https://github.com/KJTsanaktsidis/perf_profiler"
  s.files       = Dir.glob("{ext,lib}/**/*").reject { IGNORED_EXTS.include? File.basename(_1) }

  s.required_ruby_version = '>= 3.3.0dev'
end
