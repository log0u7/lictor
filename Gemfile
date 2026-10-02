# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# augure is not published yet; resolve the sibling mono-repo checkout.
gem "augure", path: "../augure"

group :development, :test do
  gem "rspec", "~> 3.13"
  gem "standard", "~> 1.56"
end
