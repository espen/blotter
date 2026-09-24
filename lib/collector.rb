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
    @rules ||= Rules.new(File.expand_path(config.fetch("rules_path"), root))
  end

  def self.reset!
    @config = @store = @rules = nil
  end
end

require_relative "collector/store"
require_relative "collector/rules"
require_relative "collector/ingest"
require_relative "collector/filter"
require_relative "collector/ingest_app"
require_relative "collector/gui"
