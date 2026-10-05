# frozen_string_literal: true

require "yaml"
require "fileutils"

module Lictor
  # The engagement registry (ADR 0003): a named target owns a directory
  # - facts, payloads, crash inputs, its own trail - and a line in
  # targets.yml. Files a human can cat, no database. --target NAME
  # scopes every command's state into the dir; the CWD-global files die.
  module Targets
    REGISTRY = "targets.yml"

    module_function

    def add(name, host_port, from: nil, bin: nil)
      raise ArgumentError, "target name must match [a-z0-9_-]+" unless name.match?(/\A[a-z0-9_-]+\z/)

      dir = File.join("targets", name)
      FileUtils.mkdir_p(dir)
      registry = load
      registry[name] = {"host" => host_port}
      registry[name]["from"] = from if from
      registry[name]["bin"] = bin if bin
      File.write(REGISTRY, registry.to_yaml)
      {dir: dir, registry: registry[name]}
    end

    def load
      File.file?(REGISTRY) ? YAML.safe_load_file(REGISTRY, permitted_classes: [], aliases: false) || {} : {}
    end

    def resolve(name)
      entry = load.fetch(name) { raise ArgumentError, "unknown target #{name.inspect} - lictor target add <name> <host:port>" }
      {dir: File.join("targets", name), host: entry["host"], from: entry["from"], bin: entry["bin"]}
    end
  end
end
