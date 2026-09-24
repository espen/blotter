require_relative "helper"
require "rack/test"

class TestIngestApp < Minitest::Test
  include TestSetup
  include Rack::Test::Methods

  def setup
    @store, @rules, = build_env
    @app = Collector::IngestApp.new(store: @store, rules: @rules, config: {
      "own_host_suffixes" => %w[example.com example.net],
      "policy_directives" => %w[default-src script-src style-src]
    })
  end

  attr_reader :app

  LEGACY = {
    "csp-report" => {
      "document-uri" => "https://ts.example.com/book?customer=42#frag",
      "effective-directive" => "script-src",
      "blocked-uri" => "https://evil.example/mal.js?key=secret",
      "script-sample" => ""
    }
  }.freeze

  MODERN = [{
    "type" => "csp-violation",
    "url" => "https://ts.example.com/book",
    "body" => {
      "documentURL" => "https://ts.example.com/book",
      "effectiveDirective" => "script-src",
      "blockedURL" => "https://evil.example/mal.js",
      "sourceFile" => "", "sample" => ""
    }
  }].freeze

  def test_legacy_format_stored_with_queries_stripped
    post "/csp", JSON.generate(LEGACY), "CONTENT_TYPE" => "application/csp-report"
    assert_equal 204, last_response.status
    row = @store.rows.first
    assert_equal "evil.example", row["blocked_key"]
    refute_includes row["sample"], "secret"
    refute_includes row["sample"], "customer=42"
  end

  def test_modern_format_stored
    post "/csp", JSON.generate(MODERN), "CONTENT_TYPE" => "application/reports+json"
    assert_equal 204, last_response.status
    assert_equal "evil.example", @store.rows.first["blocked_key"]
  end

  def test_nel_report_stored_generically
    nel = [{ "type" => "network-error", "url" => "https://ts.example.com/x",
             "body" => { "type" => "dns.name_not_resolved" } }]
    post "/csp", JSON.generate(nel), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "network-error", row["type"]
    assert_equal "dns.name_not_resolved", row["directive"]
  end

  def test_oversized_body_dropped
    post "/csp", "x" * (17 * 1024), "CONTENT_TYPE" => "application/csp-report"
    assert_equal 204, last_response.status
    assert_empty @store.rows
  end

  def test_garbage_gets_204_and_nothing_stored
    post "/csp", "not json {{", "CONTENT_TYPE" => "application/csp-report"
    assert_equal 204, last_response.status
    assert_empty @store.rows
  end

  def test_get_is_204_no_content_reflected
    get "/csp"
    assert_equal 204, last_response.status
    assert_empty last_response.body
  end

  def test_unattributed_inline_dedupes_on_sample
    %w[alpha beta].each do |sample|
      report = { "csp-report" => LEGACY["csp-report"].merge(
        "blocked-uri" => "inline", "script-sample" => "window.#{sample}"
      ) }
      post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/csp-report"
    end
    inline_rows = @store.rows.select { |r| r["bucket"] == "unattributed_inline" }
    assert_equal 2, inline_rows.size
    assert_equal ["inline:window.alpha", "inline:window.beta"], inline_rows.map { |r| r["blocked_key"] }.sort
  end

  def test_foreign_document_counted_as_structural_drop
    foreign = { "csp-report" => LEGACY["csp-report"].merge("document-uri" => "https://scanner.example/") }
    post "/csp", JSON.generate(foreign), "CONTENT_TYPE" => "application/csp-report"
    assert_empty @store.rows
    assert_equal 1, @store.rule_hit_totals["structural:foreign-document"]
  end
end
