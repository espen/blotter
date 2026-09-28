require "fileutils"
require "sqlite3"

module Collector
  # Deduped report rows + rule hit counters + daily new-key cap state.
  # Two processes (ingest + GUI) share the file; WAL handles that.
  class Store
    OVERFLOW_KEY = { type: "overflow", directive: "", blocked_key: "", document_host: "", bucket: "overflow", disposition: "" }.freeze

    SCHEMA = <<~SQL
      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY,
        type TEXT NOT NULL,
        directive TEXT NOT NULL DEFAULT '',
        blocked_key TEXT NOT NULL DEFAULT '',
        document_host TEXT NOT NULL DEFAULT '',
        bucket TEXT NOT NULL DEFAULT 'normal',
        disposition TEXT NOT NULL DEFAULT '',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 1,
        sample TEXT NOT NULL,
        UNIQUE(type, directive, blocked_key, document_host, bucket, disposition)
      );
      CREATE INDEX IF NOT EXISTS idx_reports_last_seen ON reports(last_seen);
      CREATE TABLE IF NOT EXISTS rule_hits (
        rule_id TEXT NOT NULL,
        day TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (rule_id, day)
      );
      CREATE TABLE IF NOT EXISTS daily_new_keys (
        day TEXT PRIMARY KEY,
        count INTEGER NOT NULL DEFAULT 0
      );
    SQL

    def initialize(path, max_new_keys_per_day:, max_rows:)
      FileUtils.mkdir_p(File.dirname(path))
      @db = SQLite3::Database.new(path)
      @db.busy_timeout = 5_000
      @db.execute("PRAGMA journal_mode = WAL")
      @db.execute_batch(SCHEMA)
      @db.results_as_hash = true
      migrate!
      @max_new_keys_per_day = max_new_keys_per_day
      @max_rows = max_rows
      @mutex = Mutex.new
    end

    # norm: {type:, directive:, blocked_key:, document_host:, bucket:, disposition:, raw:}
    # Returns :recorded or :overflow.
    def record(norm)
      now = Time.now.utc.iso8601
      @mutex.synchronize do
        @db.transaction do
          if bump(norm, now)
            :recorded
          elsif new_keys_today(now) >= @max_new_keys_per_day || total_rows >= @max_rows
            bump(OVERFLOW_KEY, now) || insert(OVERFLOW_KEY, now, { "note" => "new-key cap reached" })
            :overflow
          else
            insert(norm, now, norm[:raw])
            count_new_key(now)
            :recorded
          end
        end
      end
    end

    def rule_hit(rule_id)
      day = Time.now.utc.iso8601[0, 10]
      @mutex.synchronize do
        @db.execute(<<~SQL, [rule_id, day])
          INSERT INTO rule_hits (rule_id, day, count) VALUES (?, ?, 1)
          ON CONFLICT(rule_id, day) DO UPDATE SET count = count + 1
        SQL
      end
    end

    def rows(limit: 500, type: nil, directive: nil, bucket: nil, disposition: nil, document_host: nil, q: nil)
      where = ["1=1"]
      args = []
      { "type" => type, "directive" => directive, "bucket" => bucket, "disposition" => disposition }.each do |col, val|
        next if val.nil? || val.empty?

        where << "#{col} = ?"
        args << val
      end
      if document_host && !document_host.empty?
        # Suffix match, same semantics as Filter.own_host? — so a configured
        # suffix like staging.example.org selects every wildcard subdomain.
        where << "(document_host = ? OR document_host LIKE ? ESCAPE '\\')"
        args << document_host << "%.#{escape_like(document_host)}"
      end
      if q && !q.empty?
        where << "(blocked_key LIKE ? ESCAPE '\\' OR document_host LIKE ? ESCAPE '\\')"
        args << "%#{escape_like(q)}%" << "%#{escape_like(q)}%"
      end
      @db.execute("SELECT * FROM reports WHERE #{where.join(" AND ")} ORDER BY last_seen DESC LIMIT ?", args + [limit])
    end

    def distinct(column)
      raise ArgumentError unless %w[type directive bucket disposition].include?(column)

      @db.execute("SELECT DISTINCT #{column} AS v FROM reports ORDER BY v").map { |r| r["v"] }.reject(&:empty?)
    end

    def row(id)
      @db.execute("SELECT * FROM reports WHERE id = ?", [Integer(id)]).first
    end

    def delete_row(id)
      @db.execute("DELETE FROM reports WHERE id = ?", [Integer(id)])
    end

    def new_since(time)
      @db.execute(<<~SQL, [time.utc.iso8601])
        SELECT * FROM reports WHERE first_seen >= ?
        ORDER BY CASE bucket WHEN 'unattributed_inline' THEN 0 ELSE 1 END, count DESC
      SQL
    end

    def rule_hit_totals(days: 7)
      since = (Time.now.utc - days * 86_400).iso8601[0, 10]
      @db.execute(<<~SQL, [since]).to_h { |r| [r["rule_id"], r["total"]] }
        SELECT rule_id, SUM(count) AS total FROM rule_hits WHERE day >= ? GROUP BY rule_id
      SQL
    end

    def prune!(days: 90)
      cutoff = (Time.now.utc - days * 86_400).iso8601
      @db.execute("DELETE FROM reports WHERE last_seen < ?", [cutoff])
      @db.execute("DELETE FROM rule_hits WHERE day < ?", [cutoff[0, 10]])
      @db.execute("DELETE FROM daily_new_keys WHERE day < ?", [cutoff[0, 10]])
    end

    private

    def escape_like(value)
      value.gsub(/[\\%_]/) { |c| "\\#{c}" }
    end

    # Adds the disposition column (and widened dedupe key) to databases created
    # before it existed. One-shot; no-op once the column is present.
    def migrate!
      cols = @db.execute("PRAGMA table_info(reports)").map { |r| r["name"] }
      return if cols.include?("disposition")

      @db.transaction do
        @db.execute("ALTER TABLE reports RENAME TO reports_old")
        @db.execute_batch(SCHEMA)
        @db.execute(<<~SQL)
          INSERT INTO reports (id, type, directive, blocked_key, document_host, bucket,
                               disposition, first_seen, last_seen, count, sample)
          SELECT id, type, directive, blocked_key, document_host, bucket,
                 CASE type WHEN 'csp-violation' THEN 'enforce' ELSE '' END,
                 first_seen, last_seen, count, sample
          FROM reports_old
        SQL
        @db.execute("DROP TABLE reports_old")
        @db.execute_batch(SCHEMA) # the rename took idx_reports_last_seen with it
      end
    end

    def bump(key, now)
      @db.execute(<<~SQL, [now, key[:type], key[:directive], key[:blocked_key], key[:document_host], key[:bucket], key[:disposition]])
        UPDATE reports SET count = count + 1, last_seen = ?
        WHERE type = ? AND directive = ? AND blocked_key = ? AND document_host = ? AND bucket = ? AND disposition = ?
      SQL
      @db.changes > 0
    end

    def insert(key, now, raw)
      @db.execute(<<~SQL, [key[:type], key[:directive], key[:blocked_key], key[:document_host], key[:bucket], key[:disposition], now, now, JSON.generate(raw)])
        INSERT INTO reports (type, directive, blocked_key, document_host, bucket, disposition, first_seen, last_seen, sample)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      SQL
    end

    def new_keys_today(now)
      @db.execute("SELECT count FROM daily_new_keys WHERE day = ?", [now[0, 10]]).dig(0, "count") || 0
    end

    def count_new_key(now)
      @db.execute(<<~SQL, [now[0, 10]])
        INSERT INTO daily_new_keys (day, count) VALUES (?, 1)
        ON CONFLICT(day) DO UPDATE SET count = count + 1
      SQL
    end

    def total_rows
      @db.execute("SELECT COUNT(*) AS c FROM reports").dig(0, "c")
    end
  end
end
