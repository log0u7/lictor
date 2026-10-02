# frozen_string_literal: true

module Lictor
  VERSION = "0.0.0"

  # Raised when an operation lacks the required authorization context.
  class Unauthorized < StandardError; end
end
