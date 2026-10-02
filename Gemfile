# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# augure is not published yet; resolve the sibling mono-repo checkout.
# Locally it lives next to lictor; in CI it is checked out inside the tree.
augure_path = ["../augure", "./augure"].find { |p| File.file?(File.join(p, "augure.gemspec")) }
gem "augure", path: augure_path

group :development, :test do
  gem "rspec", "~> 3.13"
  gem "standard", "~> 1.56"
end
