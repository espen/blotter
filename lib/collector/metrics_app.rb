module Collector
  # GET-only Prometheus scrape endpoint. Mounted at /metrics only when
  # metrics_password is set (config.ru), behind basic auth there — same
  # pattern as /admin. Exposes operational detail, so never leave it open.
  class MetricsApp
    def initialize(metrics: Collector.metrics, store: Collector.store)
      @metrics = metrics
      @store = store
    end

    def call(env)
      return [405, { "allow" => "GET" }, []] unless env["REQUEST_METHOD"] == "GET"

      [200, { "content-type" => "text/plain; version=0.0.4; charset=utf-8" },
       [@metrics.to_text(@store)]]
    end
  end
end
