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

  def test_permissions_policy_report_keeps_feature_and_disposition
    report = [{ "type" => "permissions-policy-violation", "url" => "https://ts.example.com/manage",
                "body" => { "featureId" => "payment", "disposition" => "enforce",
                            "sourceFile" => "https://ts.example.com/app.js?v=3" } }]
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "permissions-policy-violation", row["type"]
    assert_equal "payment", row["directive"]
    assert_equal "enforce", row["disposition"]
    assert_equal "", row["blocked_key"]
    sample = JSON.parse(row["sample"])
    assert_equal "https://ts.example.com/app.js", sample["source_file"]
  end

  def test_permissions_policy_report_falls_back_to_policy_id
    report = [{ "type" => "permissions-policy-violation", "url" => "https://ts.example.com/manage",
                "body" => { "policyId" => "geolocation", "disposition" => "report" } }]
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "geolocation", row["directive"]
    assert_equal "report", row["disposition"]
  end

  def test_crash_report_keeps_reason
    report = [{ "type" => "crash", "url" => "https://ts.example.com/manage",
                "body" => { "reason" => "oom" } }]
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "crash", row["type"]
    assert_equal "oom", row["directive"]
  end

  def test_integrity_violation_keeps_blocked_url_and_report_only
    report = [{ "type" => "integrity-violation", "url" => "https://ts.example.com/manage",
                "body" => { "documentURL" => "https://ts.example.com/manage",
                            "blockedURL" => "https://cdn.example.org/lib.js?v=9",
                            "destination" => "script", "reportOnly" => true } }]
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "script", row["directive"]
    assert_equal "cdn.example.org", row["blocked_key"]
    assert_equal "report", row["disposition"]
  end

  def test_deprecation_keeps_source_file_and_message
    report = [{ "type" => "deprecation", "url" => "https://ts.example.com/manage",
                "body" => { "id" => "UnloadHandler", "message" => "Unload event listeners are deprecated",
                            "sourceFile" => "https://ts.example.com/app.js?v=3" } }]
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "UnloadHandler", row["directive"]
    sample = JSON.parse(row["sample"])
    assert_equal "https://ts.example.com/app.js", sample["source_file"]
    assert_equal "Unload event listeners are deprecated", sample["sample"]
  end

  def test_coep_keeps_blocked_url_and_reporting_disposition
    report = [{ "type" => "coep", "url" => "https://ts.example.com/manage",
                "body" => { "type" => "corp", "blockedURL" => "https://images.example.org/a.png",
                            "disposition" => "reporting" } }]
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "corp", row["directive"]
    assert_equal "images.example.org", row["blocked_key"]
    assert_equal "report", row["disposition"]
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

  def test_disposition_defaults_to_enforce
    post "/csp", JSON.generate(LEGACY), "CONTENT_TYPE" => "application/csp-report"
    assert_equal "enforce", @store.rows.first["disposition"]
  end

  def test_report_only_disposition_stored_as_separate_key
    post "/csp", JSON.generate(LEGACY), "CONTENT_TYPE" => "application/csp-report"
    report_only = { "csp-report" => LEGACY["csp-report"].merge("disposition" => "report") }
    post "/csp", JSON.generate(report_only), "CONTENT_TYPE" => "application/csp-report"
    rows = @store.rows
    assert_equal 2, rows.size
    assert_equal %w[enforce report], rows.map { |r| r["disposition"] }.sort
  end

  def test_modern_format_report_only_disposition
    modern = [{ "type" => "csp-violation", "url" => "https://ts.example.com/book",
                "body" => MODERN.first["body"].merge("disposition" => "report") }]
    post "/csp", JSON.generate(modern), "CONTENT_TYPE" => "application/reports+json"
    row = @store.rows.first
    assert_equal "report", row["disposition"]
    assert_includes row["sample"], '"disposition":"report"'
  end

  def test_non_csp_types_have_no_disposition
    nel = [{ "type" => "network-error", "url" => "https://ts.example.com/x",
             "body" => { "type" => "dns.name_not_resolved" } }]
    post "/csp", JSON.generate(nel), "CONTENT_TYPE" => "application/reports+json"
    assert_equal "", @store.rows.first["disposition"]
  end

  def test_foreign_document_counted_as_structural_drop
    foreign = { "csp-report" => LEGACY["csp-report"].merge("document-uri" => "https://scanner.example/") }
    post "/csp", JSON.generate(foreign), "CONTENT_TYPE" => "application/csp-report"
    assert_empty @store.rows
    assert_equal 1, @store.rule_hit_totals["structural:foreign-document"]
  end

  def test_cors_preflight_gets_cors_headers
    options "/csp", {}, "HTTP_ORIGIN" => "https://ts.example.com",
                        "HTTP_ACCESS_CONTROL_REQUEST_METHOD" => "POST",
                        "HTTP_ACCESS_CONTROL_REQUEST_HEADERS" => "content-type"
    assert_equal 204, last_response.status
    assert_equal "*", last_response.headers["access-control-allow-origin"]
    assert_equal "POST", last_response.headers["access-control-allow-methods"]
    assert_equal "Content-Type", last_response.headers["access-control-allow-headers"]
  end

  def test_post_response_carries_cors_headers
    post "/csp", JSON.generate(MODERN), "CONTENT_TYPE" => "application/reports+json"
    assert_equal 204, last_response.status
    assert_equal "*", last_response.headers["access-control-allow-origin"]
  end

  def test_non_object_json_answers_204
    ["[1]", "5", "null", "\"x\""].each do |body|
      post "/csp", body, "CONTENT_TYPE" => "application/csp-report"
      assert_equal 204, last_response.status, body
    end
    assert_empty @store.rows
  end

  def test_invalid_utf8_is_scrubbed_not_500
    body = JSON.generate(LEGACY).sub("mal.js", "mal\xFF.js".b).b
    post "/csp", body, "CONTENT_TYPE" => "application/csp-report"
    assert_equal 204, last_response.status
    assert_equal "evil.example", @store.rows.first["blocked_key"]
    assert_includes JSON.parse(@store.rows.first["sample"])["blocked"], "mal.js"
  end

  def test_control_characters_cannot_forge_digest_lines
    report = { "csp-report" => LEGACY["csp-report"].merge("blocked-uri" => "inline\n1000x script-src evil.example") }
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/csp-report"
    assert_equal 204, last_response.status
    assert_equal "inline 1000x script-src evil.example", @store.rows.first["blocked_key"]
  end
end
