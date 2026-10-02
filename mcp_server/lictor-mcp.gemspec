# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "lictor-mcp"
  spec.version = "0.1.0"
  spec.authors = ["Gregory Epp"]
  spec.email = ["log0u7@users.noreply.github.com"]
  spec.license = "MIT"

  spec.summary = "Gated MCP surface for the lictor orchestrator - the LLM harness's hands."
  spec.description = "MCP tools over the lictor orchestrator: scan, profile, plan, fuzz, " \
                     "execute and rule_install - all validated SERVER-side (allowlist, " \
                     "consent tokens, corpus guard) and fully trailed. The LLM proposes; " \
                     "augure disposes; lictor executes; nothing escapes the gates."
  spec.homepage = "https://github.com/log0u7/lictor"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb")
  spec.bindir = "exe"
  spec.executables = ["lictor-mcp"]
  spec.require_paths = ["lib"]

  spec.add_dependency "lictor", ">= 0.1.0"
  spec.add_dependency "mcp", "~> 1.6"
end
