ENV["COLLECTOR_CONFIG"] = File.expand_path("config.test.yml", __dir__)
require "minitest/autorun"
require "tmpdir"
require_relative "../lib/collector"

module TestSetup
  def build_env
    dir = Dir.mktmpdir
    store = Collector::Store.new(File.join(dir, "test.sqlite3"), max_new_keys_per_day: 5, max_rows: 100)
    rules = Collector::Rules.new(File.join(dir, "rules.yml"))
    [store, rules, dir]
  end

  def norm(over = {})
    {
      type: "csp-violation", directive: "script-src", blocked: "https://evil.example/x.js",
      blocked_host: "evil.example", blocked_key: "evil.example", source_file: "",
      document_uri: "https://ts.example.com/book", document_host: "ts.example.com",
      disposition: "enforce", sample: "", raw: { "blocked" => "https://evil.example/x.js" }
    }.merge(over)
  end
end
