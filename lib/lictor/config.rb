# frozen_string_literal: true

require "yaml"

module Lictor
  # Project config: lictor.yml in the working directory (or an explicit
  # path). Command-line flags override it. The engagement setup is
  # written once; the commands stay short.
  module Config
    DEFAULT_PATH = "lictor.yml"

    module_function

    def load(path = DEFAULT_PATH)
      return {} unless File.file?(path)

      settings = YAML.safe_load_file(path)
      raise ArgumentError, "lictor.yml: symbol keys are not supported - write plain \"key: value\" lines" if settings&.any? { |k, _| k.is_a?(Symbol) }
      settings.to_h.transform_keys(&:to_sym)
    rescue Psych::Exception => e
      raise ArgumentError, "lictor.yml is not parseable config: #{e.message}"
    end
  end
end
