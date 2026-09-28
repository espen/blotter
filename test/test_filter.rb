require_relative "helper"

class TestFilter < Minitest::Test
  include TestSetup

  def setup
    @store, @rules, = build_env
    @rules.add("hosts", "translate.googleapis.com")
    @opts = { rules: @rules, own_host_suffixes: %w[example.com example.net], policy_directives: %w[script-src style-src] }
  end

  def evaluate(n) = Collector::Filter.evaluate(n, **@opts)

  def test_extension_scheme_in_source_file_drops
    File.write(@rules.instance_variable_get(:@path), YAML.dump(
      { "schemes" => ["chrome-extension:"], "hosts" => [], "host_suffixes" => [], "samples" => [] }
    ))
    n = norm(source_file: "chrome-extension://abc/inject.js", blocked: "inline", blocked_host: "", blocked_key: "inline")
    verdict, rule = evaluate(n)
    assert_equal :drop, verdict
    assert_equal "schemes:chrome-extension:", rule
  end

  def test_redacted_bare_extension_scheme_in_source_file_drops
    File.write(@rules.instance_variable_get(:@path), YAML.dump(
      { "schemes" => ["chrome-extension:"], "hosts" => [], "host_suffixes" => [], "samples" => [] }
    ))
    n = norm(directive: "base-uri", source_file: "chrome-extension",
             blocked: "https://ts.example.com/book", blocked_host: "ts.example.com",
             blocked_key: "ts.example.com")
    verdict, rule = evaluate(n)
    assert_equal :drop, verdict
    assert_equal "schemes:chrome-extension:", rule
  end

  def test_host_blocklist_drops
    verdict, rule = evaluate(norm(blocked_host: "translate.googleapis.com", blocked_key: "translate.googleapis.com"))
    assert_equal :drop, verdict
    assert_equal "hosts:translate.googleapis.com", rule
  end

  def test_url_prefix_drops_but_other_paths_on_host_pass
    File.write(@rules.instance_variable_get(:@path), YAML.dump(
      { "schemes" => [], "hosts" => [], "host_suffixes" => [],
        "url_prefixes" => ["https://www.gstatic.com/_/translate_http/"], "samples" => [] }
    ))
    translate = norm(blocked: "https://www.gstatic.com/_/translate_http/_/ss/k=translate_http.tr.zZ.L.W.O",
                     blocked_host: "www.gstatic.com", blocked_key: "www.gstatic.com")
    verdict, rule = evaluate(translate)
    assert_equal :drop, verdict
    assert_equal "url_prefixes:https://www.gstatic.com/_/translate_http/", rule

    recaptcha = norm(blocked: "https://www.gstatic.com/recaptcha/api.js",
                     blocked_host: "www.gstatic.com", blocked_key: "www.gstatic.com")
    assert_equal [:store, "normal"], evaluate(recaptcha)
  end

  def test_foreign_document_drops
    verdict, rule = evaluate(norm(document_host: "scanner.example"))
    assert_equal :drop, verdict
    assert_equal "structural:foreign-document", rule
  end

  def test_unknown_directive_drops
    verdict, rule = evaluate(norm(directive: "worker-src"))
    assert_equal :drop, verdict
    assert_equal "structural:unknown-directive", rule
  end

  def test_missing_directive_drops
    verdict, rule = evaluate(norm(directive: ""))
    assert_equal :drop, verdict
    assert_equal "structural:malformed", rule
  end

  def test_unattributed_inline_bucketed_not_dropped
    n = norm(blocked: "inline", blocked_host: "", blocked_key: "inline", source_file: "", sample: "window.loop11")
    assert_equal [:store, "unattributed_inline"], evaluate(n)
  end

  def test_inline_with_ignored_sample_drops
    @rules.add("samples", "window.loop11")
    n = norm(blocked: "inline", blocked_host: "", blocked_key: "inline", sample: "window.loop11")
    verdict, rule = evaluate(n)
    assert_equal :drop, verdict
    assert_equal "samples:window.loop11", rule
  end

  def test_clean_report_stored_normal
    assert_equal [:store, "normal"], evaluate(norm)
  end

  def test_subdomain_counts_as_own
    assert_equal [:store, "normal"], evaluate(norm(document_host: "foo.dev.example.net"))
  end
end
