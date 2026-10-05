# The whole app on one port:  puma -p 9292
#   POST /csp    public ingest endpoint
#   /admin/...   GUI, mounted only when gui_password is set (basic auth)
#   /metrics     Prometheus, mounted only when metrics_password is set (basic auth)
require_relative "lib/collector"

map "/csp" do
  run Collector::IngestApp.new
end

if Collector.config["gui_password"].to_s.empty?
  warn "blotter: gui_password not set — /admin is disabled"
else
  map "/admin" do
    run Collector::GUI
  end
end

metrics_password = Collector.config["metrics_password"].to_s
unless metrics_password.empty?
  map "/metrics" do
    use Rack::Auth::Basic, "Blotter" do |_user, pass|
      Rack::Utils.secure_compare(metrics_password, pass.to_s)
    end
    run Collector::MetricsApp.new
  end
end
