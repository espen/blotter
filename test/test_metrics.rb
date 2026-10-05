require_relative "helper"
require "rack/test"

class TestMetrics < Minitest::Test
  include TestSetup
  include Rack::Test::Methods

  def setup
    @store, @rules, = build_env
    @metrics = Collector::Metrics.new
    @ingest = Collector::IngestApp.new(store: @store, rules: @rules, metrics: @metrics, config: {
      "own_host_suffixes" => %w[example.com],
      "policy_directives" => %w[script-src]
    })
    # The /metrics mount shape from config.ru: basic auth around MetricsApp.
    metrics_app = Collector::MetricsApp.new(metrics: @metrics, store: @store)
    @app = Rack::Builder.new do
      use Rack::Auth::Basic, "Blotter" do |_user, pass|
        Rack::Utils.secure_compare("scrape-password", pass.to_s)
      end
      run metrics_app
    end
  end

  attr_reader :app

  def modern(type: "csp-violation", body: {})
    default = { "documentURL" => "https://ts.example.com/book",
                "effectiveDirective" => "script-src",
                "blockedURL" => "https://evil.example/mal.js" }
    [{ "type" => type, "url" => "https://ts.example.com/book", "body" => default.merge(body) }]
  end

  def ingest(reports)
    @ingest.call(Rack::MockRequest.env_for("/csp", method: "POST",
                                                   "CONTENT_TYPE" => "application/reports+json",
                                                   input: JSON.generate(reports)))
  end

  def text = @metrics.to_text(@store)

  def test_recorded_counter_labeled_by_type_bucket_disposition
    2.times { ingest(modern) }
    assert_includes text, "blotter_reports_received_total 2"
    assert_includes text, 'blotter_reports_recorded_total{type="csp-violation",bucket="normal",disposition="enforce"} 2'
  end

  def test_dropped_counter_labeled_by_rule_class_only
    @rules.add("hosts", "evil.example")
    ingest(modern)
    foreign = modern.map { |r| r.merge("url" => "https://scanner.example/", "body" => r["body"].merge("documentURL" => "https://scanner.example/")) }
    ingest(foreign)
    assert_includes text, 'blotter_reports_dropped_total{class="hosts"} 1'
    assert_includes text, 'blotter_reports_dropped_total{class="structural"} 1'
    refute_includes text, "evil.example"
  end

  def test_unknown_type_collapses_into_other_label
    ingest(modern(type: "weird\\injected\"type", body: { "type" => "x" }))
    assert_includes text, 'blotter_reports_recorded_total{type="other",bucket="normal",disposition=""} 1'
    refute_includes text, "injected"
  end

  def test_overflow_counted_separately_from_recorded
    # build_env caps new keys at 5/day; the 6th key overflows.
    6.times { |i| ingest(modern(body: { "blockedURL" => "https://evil#{i}.example/x.js" })) }
    assert_includes text, "blotter_reports_overflow_total 1"
    assert_includes text, "blotter_reports_received_total 6"
  end

  def test_gauges_come_from_store
    ingest(modern)
    assert_includes text, "blotter_db_rows 1"
    assert_includes text, "blotter_new_keys_today 1"
  end

  def test_scrape_requires_auth
    get "/"
    assert_equal 401, last_response.status
  end

  def test_scrape_with_password_returns_exposition_format
    ingest(modern)
    basic_authorize "x", "scrape-password"
    get "/"
    assert_equal 200, last_response.status
    assert_includes last_response.headers["content-type"], "text/plain"
    assert_includes last_response.body, "# TYPE blotter_reports_received_total counter"
    assert_includes last_response.body, "blotter_db_rows 1"
  end

  def test_scrape_is_get_only
    basic_authorize "x", "scrape-password"
    post "/"
    assert_equal 405, last_response.status
    assert_empty last_response.body
  end
end
