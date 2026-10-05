# frozen_string_literal: true

require_relative "lib/lictor/version"

Gem::Specification.new do |spec|
  spec.name = "lictor"
  spec.version = Lictor::VERSION
  spec.authors = ["Gregory Epp"]
  spec.email = ["log0u7@users.noreply.github.com"]
  spec.license = "MIT"

  spec.summary = "The orchestrator that carries out augure's judgments - handoff by default, everything trailed."
  spec.description = "Carries out the decisions augure judged: handoff by default, " \
                     "everything trailed, the operator is the authorization. Scan, " \
                     "acquire, fuzz, verify, plan, build, run, report. Lictor " \
                     "executes; it never decides."
  spec.homepage = "https://github.com/log0u7/lictor"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir.glob(File.expand_path("lib", __dir__) + "/**/*.rb") + Dir.glob(File.expand_path("lib", __dir__) + "/config/*.yml") + Dir.glob(File.expand_path("lib", __dir__) + "/lictor/templates/*.erb") + [File.expand_path("bin/lictor", __dir__), "LICENSE", "README.md", "CHANGELOG.md"]
  spec.bindir = "bin"
  spec.executables = ["lictor"]
  spec.require_paths = ["lib"]

  spec.add_dependency "augure", ">= 0.1.0"
  spec.add_dependency "ruby-nmap", "~> 1.0"
end
