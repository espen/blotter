require "sinatra/base"
require "rack/protection"

module Collector
  # Internal GUI, mounted at /admin behind basic auth (see config.ru).
  # All output escaped (erubi escape_html),
  # CSRF on every form. Rule values are never taken from the request — only
  # row IDs; values are re-extracted server-side from stored reports.
  class GUI < Sinatra::Base
    set :views, File.expand_path("../../views", __dir__)
    set :public_folder, File.expand_path("../../public", __dir__)
    set :static, true
    set :erb, escape_html: true
    set :show_exceptions, false
    set :prefixed_redirects, true
    # Reachability is controlled by binding to the WireGuard interface, not by
    # Host-header checks — the GUI is reached by bare IP, so no fixed hostname.
    set :host_authorization, permitted_hosts: []

    # In-app auth: set gui_password in config.yml. Basic auth sends the
    # password on every request — only ever expose the GUI over HTTPS.
    gui_password = Collector.config["gui_password"].to_s
    unless gui_password.empty?
      use Rack::Auth::Basic, "Blotter" do |_user, pass|
        Rack::Utils.secure_compare(gui_password, pass.to_s)
      end
    end

    use Rack::Session::Cookie,
        key: "blotter",
        secret: Collector.config.fetch("session_secret"),
        same_site: :strict,
        http_only: true
    use Rack::Protection::AuthenticityToken

    IGNORE_KINDS = { "type_directive" => "type_directives", "scheme" => "schemes",
                     "host" => "hosts", "sample" => "samples" }.freeze

    helpers do
      def csrf_token
        Rack::Protection::AuthenticityToken.token(session)
      end

      def store = Collector.store
      def rules = Collector.rules
      def site_title = Collector.config.fetch("title", "")
      def own_host_suffixes = Collector.config.fetch("own_host_suffixes", [])

      # Which "ignore" actions apply to a row — computed from the
      # stored report, so the GUI can only promote observed values.
      def ignore_options(row)
        sample = JSON.parse(row["sample"])
        opts = {}
        scheme = extract_scheme(sample)
        opts["scheme"] = scheme if scheme
        host = row["blocked_key"] if row["blocked_key"] =~ Rules::HOST_RE
        opts["host"] = host if host
        opts["sample"] = sample["sample"] if row["bucket"] == "unattributed_inline" && !sample["sample"].to_s.empty?
        # type/directive classes only for non-CSP reports — a CSP directive
        # ("script-src") is far too broad to mute wholesale from the GUI.
        if row["type"] != "csp-violation" && !row["directive"].empty?
          opts["type_directive"] = "#{row["type"]}/#{row["directive"]}"
        end
        opts
      end

      def extract_scheme(sample)
        [sample["blocked"], sample["source_file"]].compact.each do |v|
          scheme = v[/\A[a-z][a-z0-9+.\-]{0,63}:/]
          return scheme if scheme && !%w[http: https:].include?(scheme)
        end
        nil
      end

      def week_ago = (Time.now.utc - 7 * 86_400).iso8601

      # inline > new-this-week > overflow > quiet — one dot, one meaning.
      def row_dot(row)
        return "inline" if row["bucket"] == "unattributed_inline"
        return "overflow" if row["bucket"] == "overflow"
        return "new" if row["first_seen"] >= week_ago

        "quiet"
      end
    end

    get "/" do
      # Filter values are matched as SQL parameters only — free text is safe.
      @filters = {
        type: params[:type].to_s, directive: params[:directive].to_s,
        bucket: params[:bucket].to_s, disposition: params[:disposition].to_s,
        document_host: params[:document_host].to_s, q: params[:q].to_s
      }
      @rows = store.rows(**@filters)
      @new_count = store.new_since(Time.now - 7 * 86_400).size
      erb :index
    end

    get "/report/:id" do
      @row = store.row(params[:id]) or halt 404, "not found"
      @options = ignore_options(@row)
      erb :report
    end

    post "/rows/:id/ignore" do
      row = store.row(params[:id]) or halt 404, "not found"
      kind = IGNORE_KINDS[params[:kind]] or halt 400, "bad kind"
      value = ignore_options(row)[params[:kind]] or halt 400, "not applicable"
      rules.add(kind, value)
      redirect "/"
    rescue Rules::InvalidRule => e
      halt 400, "invalid rule: #{Rack::Utils.escape_html(e.message)}"
    end

    post "/rows/:id/delete" do
      store.delete_row(params[:id])
      redirect "/"
    end

    get "/rules" do
      @rules = rules.data
      @hits = store.rule_hit_totals
      erb :rules
    end

    post "/rules/delete" do
      kind = params[:kind]
      halt 400, "bad kind" unless Rules::KINDS.include?(kind)
      halt 404, "no such rule" unless rules.data[kind].include?(params[:value])
      rules.delete(kind, params[:value])
      redirect "/rules"
    end
  end
end
