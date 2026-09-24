require "tempfile"

module Collector
  # YAML rules file: exact-match values only, hot-reloaded on mtime change.
  # Writes go through validate -> flock -> load -> mutate -> atomic replace.
  # Values originate from attacker-controlled reports; they are only ever
  # serialized via YAML.dump of plain strings — never appended as text.
  class Rules
    KINDS = %w[schemes hosts host_suffixes samples].freeze
    GUI_KINDS = %w[schemes hosts samples].freeze # host_suffixes is hand-edit only
    SCHEME_RE = /\A[a-z][a-z0-9+.\-]{0,63}:\z/
    HOST_RE = /\A(?=.{1,253}\z)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\z/i
    SAMPLE_MAX = 40

    class InvalidRule < StandardError; end

    def initialize(path)
      @path = path
      @mutex = Mutex.new
      @mtime = nil
      @data = empty
      reload_if_changed
    end

    def data
      reload_if_changed
      @data
    end

    # Returns a rule id ("hosts:evil.example") or nil.
    def match(norm)
      d = data
      d["schemes"].each do |s|
        return "schemes:#{s}" if norm[:blocked].start_with?(s) || norm[:source_file].start_with?(s)
      end
      d["hosts"].each do |h|
        return "hosts:#{h}" if norm[:blocked_host] == h
      end
      d["host_suffixes"].each do |h|
        bh = norm[:blocked_host]
        return "host_suffixes:#{h}" if bh == h || bh.end_with?(".#{h}")
      end
      d["samples"].each do |s|
        return "samples:#{s}" if !norm[:sample].empty? && norm[:sample] == s
      end
      nil
    end

    def add(kind, value)
      raise InvalidRule, "unknown kind" unless GUI_KINDS.include?(kind)
      value = validate!(kind, value)
      mutate { |d| d[kind] << value unless d[kind].include?(value) }
    end

    def delete(kind, value)
      raise InvalidRule, "unknown kind" unless KINDS.include?(kind)
      mutate { |d| d[kind].delete(value) }
    end

    def validate!(kind, value)
      value = value.to_s
      case kind
      when "schemes"
        raise InvalidRule, "not a scheme" unless value.match?(SCHEME_RE)
      when "hosts", "host_suffixes"
        raise InvalidRule, "not a hostname" unless value.match?(HOST_RE)
      when "samples"
        raise InvalidRule, "empty sample" if value.empty?
        raise InvalidRule, "sample too long" if value.length > SAMPLE_MAX
        raise InvalidRule, "non-printable sample" unless value.match?(/\A[[:print:]]+\z/)
      end
      value
    end

    private

    def empty
      KINDS.to_h { |k| [k, []] }
    end

    def reload_if_changed
      @mutex.synchronize do
        mtime = File.exist?(@path) ? File.mtime(@path) : nil
        return if mtime == @mtime

        @data = load_file
        @mtime = mtime
      end
    end

    def load_file
      return empty unless File.exist?(@path)

      raw = YAML.safe_load(File.read(@path), aliases: false) || {}
      empty.merge(raw.slice(*KINDS)) { |_k, base, vals| Array(vals).map(&:to_s) | base }
    end

    def mutate
      @mutex.synchronize do
        File.open(@path, File::RDWR | File::CREAT, 0o600) do |f|
          f.flock(File::LOCK_EX)
          d = load_file
          yield d
          write_atomic(d)
          @data = d
          @mtime = File.mtime(@path)
        end
      end
    end

    def write_atomic(d)
      Tempfile.create("rules", File.dirname(@path)) do |tmp|
        tmp.write(YAML.dump(d))
        tmp.fsync
        File.rename(tmp.path, @path)
        File.chmod(0o600, @path)
      end
    rescue Errno::ENOENT
      # Tempfile.create raises unlinking the renamed file; the rename succeeded.
    end
  end
end
