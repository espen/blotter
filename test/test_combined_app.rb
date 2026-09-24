require_relative "helper"
require "rack/test"

# The production shape from config.ru: /csp public, /admin behind basic auth.
class TestCombinedApp < Minitest::Test
  include TestSetup
  include Rack::Test::Methods

  def app
    @app ||= begin
      store, rules, = build_env
      ingest = Collector::IngestApp.new(store: store, rules: rules, config: {
        "own_host_suffixes" => %w[example.com],
        "policy_directives" => %w[script-src]
      })
      Rack::URLMap.new("/csp" => ingest, "/admin" => Collector::GUI)
    end
  end

  def test_csp_posts_reach_ingest
    report = { "csp-report" => { "document-uri" => "https://ts.example.com/",
                                 "effective-directive" => "script-src",
                                 "blocked-uri" => "https://evil.example/x.js" } }
    post "/csp", JSON.generate(report), "CONTENT_TYPE" => "application/csp-report"
    assert_equal 204, last_response.status
  end

  def test_admin_requires_auth_when_password_set
    skip "gui_password not set in test config" if Collector.config["gui_password"].to_s.empty?
    get "/admin/"
    assert_equal 401, last_response.status
  end

  def test_admin_with_password_and_prefixed_links
    password = Collector.config["gui_password"].to_s
    skip "gui_password not set in test config" if password.empty?
    basic_authorize "x", password
    get "/admin/"
    assert_equal 200, last_response.status
    assert_includes last_response.body, "/admin/rules"
  end
end
