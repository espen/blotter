module Collector
  # Parses the two wire formats and normalizes each report into a plain hash:
  #   type:          "csp-violation", "network-error", "deprecation", ...
  #   directive:     effective/violated directive (csp) or body subtype (others)
  #   blocked:       full blocked value, query/fragment stripped
  #   blocked_host:  host if blocked is a URL, else ""
  #   blocked_key:   dedupe component — host for URLs, full value otherwise
  #   source_file:   query-stripped source file (csp)
  #   document_uri:  query-stripped document/page URL
  #   document_host: host of document_uri
  #   disposition:   "enforce"/"report" (csp, permissions/document-policy), "" for other types
  #   sample:        script-sample (csp), truncated
  #   raw:           minimized report stored as the sample JSON
  module Ingest
    MAX_REPORTS_PER_POST = 50
    NON_URL_VALUES = ["inline", "eval", "data", "blob", "asset", ""].freeze

    module_function

    def parse(content_type, body)
      json = JSON.parse(body)
      case content_type.to_s.split(";").first&.strip
      when "application/csp-report", "application/json"
        return [] unless json.is_a?(Hash)

        report = json["csp-report"]
        report.is_a?(Hash) ? [normalize_legacy(report)] : []
      when "application/reports+json"
        return [] unless json.is_a?(Array)

        json.first(MAX_REPORTS_PER_POST).filter_map { |item| normalize_report_api(item) }
      else
        []
      end
    end

    def normalize_legacy(r)
      directive = str(r["effective-directive"]).empty? ? str(r["violated-directive"]) : str(r["effective-directive"])
      build(
        type: "csp-violation",
        directive: directive.split.first.to_s,
        blocked: str(r["blocked-uri"]),
        source_file: str(r["source-file"]),
        document_uri: str(r["document-uri"]),
        disposition: csp_disposition(r["disposition"]),
        sample: str(r["script-sample"])
      )
    end

    def normalize_report_api(item)
      return nil unless item.is_a?(Hash) && item["body"].is_a?(Hash)

      body = item["body"]
      type = str(item["type"])
      return nil if type.empty?

      if type == "csp-violation"
        build(
          type: type,
          directive: str(body["effectiveDirective"]).split.first.to_s,
          blocked: str(body["blockedURL"]),
          source_file: str(body["sourceFile"]),
          document_uri: str(body["documentURL"]).empty? ? str(item["url"]) : str(body["documentURL"]),
          disposition: csp_disposition(body["disposition"]),
          sample: str(body["sample"])
        )
      elsif %w[permissions-policy-violation document-policy-violation].include?(type)
        # Body carries the violated feature in featureId (policyId in older
        # Chrome); nothing is "blocked" in the CSP sense, so blocked stays "".
        build(
          type: type,
          directive: str(body["featureId"]).empty? ? str(body["policyId"]) : str(body["featureId"]),
          blocked: "",
          source_file: str(body["sourceFile"]),
          document_uri: str(item["url"]),
          disposition: csp_disposition(body["disposition"]),
          sample: ""
        )
      else
        # Generic Reporting API types (network-error, deprecation, crash, ...)
        build(
          type: type,
          directive: str(body["type"]).empty? ? str(body["id"]) : str(body["type"]),
          blocked: str(item["url"]),
          source_file: "",
          document_uri: str(item["url"]),
          disposition: "",
          sample: ""
        )
      end
    end

    # Absent disposition means an old browser enforcing — "report" is the only
    # value that changes what a violation means (hypothetical, not a real block).
    def csp_disposition(v)
      v == "report" ? "report" : "enforce"
    end

    def build(type:, directive:, blocked:, source_file:, document_uri:, disposition:, sample:)
      blocked = strip_query(blocked)
      document_uri = strip_query(document_uri)
      source_file = strip_query(source_file)
      blocked_host = host_of(blocked)
      {
        type: type[0, 64],
        directive: directive[0, 64],
        blocked: blocked[0, 512],
        blocked_host: blocked_host,
        blocked_key: blocked_host.empty? ? blocked[0, 128] : blocked_host,
        source_file: source_file[0, 512],
        document_uri: document_uri[0, 512],
        document_host: host_of(document_uri),
        disposition: disposition,
        sample: sample[0, Rules::SAMPLE_MAX],
        raw: {
          "type" => type[0, 64],
          "directive" => directive[0, 64],
          "blocked" => blocked[0, 512],
          "source_file" => source_file[0, 512],
          "document_uri" => document_uri[0, 512],
          "disposition" => disposition,
          "sample" => sample[0, Rules::SAMPLE_MAX]
        }
      }
    end

    # Invalid UTF-8 would raise in regex/JSON.generate downstream — drop the bad bytes.
    # Control characters (newlines) would let a report forge lines in the digest.
    def str(v)
      v.is_a?(String) ? v.scrub("").gsub(/[[:cntrl:]]/, " ") : ""
    end

    # GDPR: query strings and fragments may carry personal data — never stored.
    def strip_query(url)
      url.split(/[?#]/, 2).first.to_s
    end

    def host_of(value)
      return "" if value.empty? || NON_URL_VALUES.include?(value)

      URI.parse(value).host.to_s.downcase
    rescue URI::Error
      ""
    end
  end
end
