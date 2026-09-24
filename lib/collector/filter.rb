module Collector
  # Rule classes from the plan, checked in order:
  #   1. scheme rules  2. host blocklist  3. structural  4. unattributed inline
  # Returns [:drop, rule_id] or [:store, bucket].
  module Filter
    module_function

    def evaluate(norm, rules:, own_host_suffixes:, policy_directives:)
      # 3a first: a foreign document-uri means a scanner/bot POSTing directly —
      # nothing else about the report can be trusted, so this precedes matching.
      return [:drop, "structural:foreign-document"] unless own_host?(norm[:document_host], own_host_suffixes)

      if (rule_id = rules.match(norm))
        return [:drop, rule_id]
      end

      if norm[:type] == "csp-violation"
        return [:drop, "structural:malformed"] if norm[:directive].empty?
        return [:drop, "structural:unknown-directive"] unless policy_directives.include?(norm[:directive])

        if unattributed_inline?(norm)
          return [:store, "unattributed_inline"]
        end
      end

      [:store, "normal"]
    end

    def own_host?(host, suffixes)
      return false if host.empty?

      suffixes.any? { |s| host == s || host.end_with?(".#{s}") }
    end

    def unattributed_inline?(norm)
      norm[:directive].start_with?("script-src") &&
        ["inline", "eval", ""].include?(norm[:blocked]) &&
        norm[:source_file].empty?
    end
  end
end
