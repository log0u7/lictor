# frozen_string_literal: true

require "augure"
require "augure/pack_loader"

module Lictor
  # Loads the operator's taught techniques (data-only packs) for use in
  # a decision. The armor runs at load time: the schema vocabulary, the
  # corpus guard - a pack that would move a frozen verdict is refused
  # here, before any decision sees it. No directory (or an empty one)
  # means built-in techniques only.
  module TechniquePacks
    module_function

    def load(dir, guard: true)
      return [] if dir.nil? || !File.directory?(dir)

      packs = Augure::PackLoader.load_dir(dir)
      Augure::PackLoader.corpus_guard(packs) if guard
      packs
    rescue Augure::PackError => e
      raise Augure::PackError, "technique packs in #{dir} refused: #{e.message}"
    end
  end
end
