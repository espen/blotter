require_relative "helper"

class TestStore < Minitest::Test
  include TestSetup

  def setup
    @store, @rules, = build_env
  end

  def test_dedupe_increments_count
    assert_equal :recorded, @store.record(norm.merge(bucket: "normal"))
    assert_equal :recorded, @store.record(norm.merge(bucket: "normal"))
    rows = @store.rows
    assert_equal 1, rows.size
    assert_equal 2, rows.first["count"]
  end

  def test_new_key_cap_overflows
    5.times { |i| @store.record(norm(blocked_key: "host#{i}.example").merge(bucket: "normal")) }
    assert_equal :overflow, @store.record(norm(blocked_key: "host-extra.example").merge(bucket: "normal"))
    assert_equal :overflow, @store.record(norm(blocked_key: "host-extra2.example").merge(bucket: "normal"))
    overflow = @store.rows.find { |r| r["bucket"] == "overflow" }
    assert_equal 2, overflow["count"]
    assert_equal 6, @store.rows.size # 5 real + 1 overflow bucket
  end

  def test_rows_filtering
    @store.record(norm.merge(bucket: "normal"))
    @store.record(norm(type: "network-error", directive: "dns.name_not_resolved", blocked_key: "cdn.other.example").merge(bucket: "normal"))
    assert_equal 1, @store.rows(type: "network-error").size
    assert_equal 1, @store.rows(q: "evil").size
    assert_equal 2, @store.rows(q: "example").size
    assert_empty @store.rows(q: "%") # LIKE wildcards escaped, matches literally
    assert_equal %w[csp-violation network-error], @store.distinct("type")
  end

  def test_rule_hits_accumulate
    @store.rule_hit("hosts:x.example")
    @store.rule_hit("hosts:x.example")
    assert_equal 2, @store.rule_hit_totals["hosts:x.example"]
  end
end

class TestRules < Minitest::Test
  include TestSetup

  def setup
    _, @rules, @dir = build_env
    @path = File.join(@dir, "rules.yml")
  end

  def test_add_and_match_host
    @rules.add("hosts", "noise.example")
    assert_equal "hosts:noise.example", @rules.match(norm(blocked_host: "noise.example"))
  end

  def test_yaml_structure_injection_becomes_plain_string
    assert_raises(Collector::Rules::InvalidRule) { @rules.add("hosts", "evil\nschemes:\n - https:") }
  end

  def test_sample_with_yaml_syntax_is_safe
    tricky = "'; schemes: [https:] #"
    @rules.add("samples", tricky)
    reloaded = Collector::Rules.new(@path)
    assert_includes reloaded.data["samples"], tricky
    refute_includes reloaded.data["schemes"], "https:"
  end

  def test_rejects_bad_scheme_and_long_sample
    assert_raises(Collector::Rules::InvalidRule) { @rules.add("schemes", "not a scheme") }
    assert_raises(Collector::Rules::InvalidRule) { @rules.add("samples", "x" * 41) }
    assert_raises(Collector::Rules::InvalidRule) { @rules.add("samples", "bad\x00byte") }
  end

  def test_gui_cannot_add_host_suffixes
    assert_raises(Collector::Rules::InvalidRule) { @rules.add("host_suffixes", "example.com") }
  end

  def test_gui_cannot_add_url_prefixes
    assert_raises(Collector::Rules::InvalidRule) { @rules.add("url_prefixes", "https://x.example/a/") }
  end

  def test_url_prefix_validation
    assert_equal "https://x.example/a/", @rules.validate!("url_prefixes", "https://x.example/a/")
    assert_raises(Collector::Rules::InvalidRule) { @rules.validate!("url_prefixes", "http://x.example/a/") }
    assert_raises(Collector::Rules::InvalidRule) { @rules.validate!("url_prefixes", "https://x.example/") }
    assert_raises(Collector::Rules::InvalidRule) { @rules.validate!("url_prefixes", "https://x.example") }
    assert_raises(Collector::Rules::InvalidRule) { @rules.validate!("url_prefixes", "https://x.example/a?b=1") }
  end

  def test_delete_rule
    @rules.add("hosts", "gone.example")
    @rules.delete("hosts", "gone.example")
    assert_nil @rules.match(norm(blocked_host: "gone.example"))
  end

  def test_hot_reload_on_file_change
    File.write(@path, YAML.dump({ "schemes" => [], "hosts" => ["edited.example"], "host_suffixes" => [], "samples" => [] }))
    FileUtils.touch(@path, mtime: Time.now + 5)
    assert_equal "hosts:edited.example", @rules.match(norm(blocked_host: "edited.example"))
  end

  def test_file_written_0600
    @rules.add("hosts", "perm.example")
    assert_equal 0o600, File.stat(@path).mode & 0o777
  end
end
