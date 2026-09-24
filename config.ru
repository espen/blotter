# The whole app on one port:  puma -p 9292
#   POST /csp    public ingest endpoint
#   /admin/...   GUI, mounted only when gui_password is set (basic auth)
require_relative "lib/collector"

map "/csp" do
  run Collector::IngestApp.new
end

if Collector.config["gui_password"].to_s.empty?
  warn "csp-collector: gui_password not set — /admin is disabled"
else
  map "/admin" do
    run Collector::GUI
  end
end
