require "rack"

module Collector
  # Public write-only endpoint. Always answers 204 — scanners and malformed
  # input get no feedback. Never reflects input, never fetches anything.
  class IngestApp
    # Chrome batches every queued report for an endpoint into one upload and
    # embeds the full originalPolicy (~1-2KB) in each CSP report, so a burst of
    # violations easily produces a 20-100KB body. Rejecting it loses the whole
    # batch AND puts the endpoint into client-side retry backoff. Work is still
    # bounded by Ingest::MAX_REPORTS_PER_POST.
    MAX_BODY = 256 * 1024

    # Reporting API uploads (report-to / NEL) are cross-origin CORS fetches —
    # without these headers on the preflight AND the POST response, browsers
    # drop every report silently. Wide-open is fine: write-only, always 204.
    CORS_HEADERS = {
      "access-control-allow-origin" => "*",
      "access-control-allow-methods" => "POST",
      "access-control-allow-headers" => "Content-Type",
      "access-control-max-age" => "86400"
    }.freeze

    def initialize(store: Collector.store, rules: Collector.rules, config: Collector.config,
                   metrics: Collector.metrics)
      @store = store
      @rules = rules
      @metrics = metrics
      @own_host_suffixes = config.fetch("own_host_suffixes")
      @policy_directives = config.fetch("policy_directives")
    end

    def call(env)
      req = Rack::Request.new(env)
      # Mounted at /csp (path_info "" or "/"), or standalone at /csp.
      return no_content unless req.post? && ["", "/", "/csp"].include?(req.path_info)

      body = req.body.read(MAX_BODY + 1).to_s
      return no_content if body.bytesize > MAX_BODY

      Ingest.parse(req.content_type, body).each { |norm| process(norm) }
      no_content
    rescue JSON::ParserError
      no_content
    end

    private

    def process(norm)
      @metrics.received!
      verdict, detail = Filter.evaluate(
        norm, rules: @rules,
        own_host_suffixes: @own_host_suffixes, policy_directives: @policy_directives
      )
      if verdict == :drop
        @store.rule_hit(detail)
        @metrics.dropped!(detail)
      else
        # Unattributed inline dedupes on the script sample — distinct injected
        # scripts must not collapse into one "inline" row per page.
        if detail == "unattributed_inline" && !norm[:sample].empty?
          norm = norm.merge(blocked_key: "inline:#{norm[:sample]}")
        end
        norm = norm.merge(bucket: detail)
        @store.record(norm) == :overflow ? @metrics.overflow! : @metrics.recorded!(norm)
      end
    end

    def no_content
      [204, CORS_HEADERS.dup, []]
    end
  end
end
