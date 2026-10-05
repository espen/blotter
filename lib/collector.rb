require "json"
require "time"
require "uri"
require "yaml"

module Collector
  CONFIG_PATH = ENV.fetch("COLLECTOR_CONFIG") { File.expand_path("../config.yml", __dir__) }

  def self.config
    @config ||= YAML.safe_load(File.read(CONFIG_PATH), aliases: false).freeze
  end

  def self.root
    File.expand_path("..", __dir__)
  end

  def self.store
    @store ||= Store.new(
      File.expand_path(config.fetch("db_path"), root),
      max_new_keys_per_day: config.fetch("max_new_keys_per_day"),
      max_rows: config.fetch("max_rows")
    )
  end

  def self.rules
    @rules ||= begin
      path = File.expand_path(config.fetch("rules_path"), root)
      seed = File.join(root, "rules.yml")
      # First boot with no live rules file (e.g. a fresh Docker volume):
      # seed it from the tracked community noise list.
      if path != seed && !File.exist?(path) && File.exist?(seed)
        require "fileutils"
        FileUtils.mkdir_p(File.dirname(path))
        FileUtils.cp(seed, path)
      end
      Rules.new(path)
    end
  end

  def self.metrics
    @metrics ||= Metrics.new
  end

  def self.reset!
    @config = @store = @rules = @metrics = nil
  end
end

require_relative "collector/store"
require_relative "collector/rules"
require_relative "collector/ingest"
require_relative "collector/filter"
require_relative "collector/ingest_app"
require_relative "collector/metrics"
require_relative "collector/metrics_app"
require_relative "collector/gui"
