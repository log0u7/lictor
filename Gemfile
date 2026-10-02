# frozen_string_literal: true

source "https://rubygems.org"

gemspec
gemspec path: "mcp_server", name: "lictor-mcp"

# augure is not published yet; resolve the sibling mono-repo checkout.
# Locally it lives next to lictor; in CI it is checked out inside the tree.
# Anchored to the Gemfile, not to the CWD: the CLI runs from anywhere.
augure_path = ["../augure", "./augure"]
  .map { |p| File.expand_path(p, __dir__) }
  .find { |p| File.file?(File.join(p, "augure.gemspec")) }
raise "augure checkout not found next to the lictor checkout" unless augure_path

gem "augure", path: augure_path
gem "augure-profiler", path: File.expand_path(File.join(augure_path, "profiler"), __dir__)

group :development, :test do
  gem "rspec", "~> 3.13"
  gem "standard", "~> 1.56"
end
