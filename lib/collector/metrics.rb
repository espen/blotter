module Collector
  # In-process Prometheus counters. Counting is always on (a mutex-guarded
  # integer bump per report, nothing more); the /metrics endpoint exposing
  # them is opt-in via metrics_password (see config.ru).
  #
  # Counters live in memory and reset on restart — an ordinary Prometheus
  # counter reset, which rate() handles. Deriving them from SQLite sums
  # instead would *fake* a reset at every prune (pruning lowers the sums),
  # producing a false rate spike.
  class Metrics
    # Report type is attacker-controlled free text; unknown values collapse
    # into "other" so a scanner can't mint unbounded Prometheus label values.
    # Every other label (rule class, bucket, disposition) is app-controlled.
    # Label values therefore never need exposition-format escaping.
    KNOWN_TYPES = %w[
      coep coop crash csp-violation deprecation document-policy-violation
      integrity-violation intervention network-error permissions-policy-violation
    ].freeze

    def initialize
      @mutex = Mutex.new
      @received = 0
      @overflow = 0
      @dropped = Hash.new(0)  # rule class: "schemes", "hosts", "structural", ...
      @recorded = Hash.new(0) # [type, bucket, disposition]
    end

    def received!
      @mutex.synchronize { @received += 1 }
    end

    # rule_id is "class:value" (Rules#match) or "structural:reason" (Filter) —
    # the class alone keeps cardinality at the handful of Rules::KINDS.
    def dropped!(rule_id)
      klass = rule_id.split(":", 2).first
      @mutex.synchronize { @dropped[klass] += 1 }
    end

    def recorded!(norm)
      type = KNOWN_TYPES.include?(norm[:type]) ? norm[:type] : "other"
      @mutex.synchronize { @recorded[[type, norm[:bucket], norm[:disposition]]] += 1 }
    end

    def overflow!
      @mutex.synchronize { @overflow += 1 }
    end

    # Prometheus text exposition format. The two gauges come from the store:
    # unlike the counters they legitimately go down (prune, deletes), which
    # gauges allow.
    def to_text(store)
      received, overflow, dropped, recorded = @mutex.synchronize do
        [@received, @overflow, @dropped.sort.to_h, @recorded.sort.to_h]
      end
      gauges = store.gauges
      <<~TEXT
        # HELP blotter_reports_received_total Reports parsed from ingest POSTs, before filtering.
        # TYPE blotter_reports_received_total counter
        blotter_reports_received_total #{received}
        # HELP blotter_reports_dropped_total Reports dropped at ingest, by rule class.
        # TYPE blotter_reports_dropped_total counter
        #{dropped.map { |klass, n| %(blotter_reports_dropped_total{class="#{klass}"} #{n}) }.join("\n")}
        # HELP blotter_reports_recorded_total Reports deduped into stored keys.
        # TYPE blotter_reports_recorded_total counter
        #{recorded.map { |(type, bucket, disp), n| %(blotter_reports_recorded_total{type="#{type}",bucket="#{bucket}",disposition="#{disp}"} #{n}) }.join("\n")}
        # HELP blotter_reports_overflow_total Reports collapsed into the overflow row (flood caps).
        # TYPE blotter_reports_overflow_total counter
        blotter_reports_overflow_total #{overflow}
        # HELP blotter_db_rows Deduped report rows currently stored.
        # TYPE blotter_db_rows gauge
        blotter_db_rows #{gauges[:rows]}
        # HELP blotter_new_keys_today New dedupe keys seen today (UTC), against max_new_keys_per_day.
        # TYPE blotter_new_keys_today gauge
        blotter_new_keys_today #{gauges[:new_keys_today]}
      TEXT
        .gsub(/^\n/, "") # label-less rounds leave blank lines; drop them
    end
  end
end
