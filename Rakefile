require "bundler/gem_tasks"
require "rake/extensiontask"


# Compile verbosely if specified.
ENV["MAKE"] = "make V=1" if ENV["VERBOSE"] == "true"

Rake::ExtensionTask.new("perf_profiler")

