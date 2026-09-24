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

  def test_host_blocklist_drops
    verdict, rule = evaluate(norm(blocked_host: "translate.googleapis.com", blocked_key: "translate.googleapis.com"))
    assert_equal :drop, verdict
    assert_equal "hosts:translate.googleapis.com", rule
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
