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

  def test_disposition_filter_and_distinct
    @store.record(norm.merge(bucket: "normal"))
    @store.record(norm(disposition: "report").merge(bucket: "normal"))
    assert_equal 2, @store.rows.size
    assert_equal 1, @store.rows(disposition: "report").size
    assert_equal %w[enforce report], @store.distinct("disposition")
  end

  def test_migration_adds_disposition_to_old_database
    path = File.join(Dir.mktmpdir, "old.sqlite3")
    db = SQLite3::Database.new(path)
    db.execute_batch(<<~SQL)
      CREATE TABLE reports (
        id INTEGER PRIMARY KEY, type TEXT NOT NULL, directive TEXT NOT NULL DEFAULT '',
        blocked_key TEXT NOT NULL DEFAULT '', document_host TEXT NOT NULL DEFAULT '',
        bucket TEXT NOT NULL DEFAULT 'normal', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 1, sample TEXT NOT NULL,
        UNIQUE(type, directive, blocked_key, document_host, bucket)
      );
      CREATE INDEX idx_reports_last_seen ON reports(last_seen);
      INSERT INTO reports (type, directive, blocked_key, document_host, bucket, first_seen, last_seen, count, sample)
      VALUES ('csp-violation', 'script-src', 'evil.example', 'ts.example.com', 'normal',
              '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 7, '{}'),
             ('network-error', 'dns.name_not_resolved', 'ts.example.com', 'ts.example.com', 'normal',
              '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 2, '{}');
    SQL
    db.close

    store = Collector::Store.new(path, max_new_keys_per_day: 5, max_rows: 100)
    rows = store.rows
    assert_equal 7, rows.find { |r| r["type"] == "csp-violation" }["count"]
    assert_equal "enforce", rows.find { |r| r["type"] == "csp-violation" }["disposition"]
    assert_equal "", rows.find { |r| r["type"] == "network-error" }["disposition"]
    # A report-only twin of the migrated key lands as its own row.
    assert_equal :recorded, store.record(norm(disposition: "report").merge(bucket: "normal"))
    assert_equal 3, store.rows.size
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
