# csp-collector

A small self-hosted collector for CSP violation reports (and any other
[Reporting API](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API)
type: NEL, deprecation, crash). Built to replace a hosted service like
report-uri.com for a single site or small fleet.

The premise: **real signal repeats, noise is endless but recognizable.**
Hundreds of identical reports mean a real problem; browser extensions,
antivirus proxies and scanners produce endless one-offs. So the collector
filters known noise at ingest, dedupes everything else into counted keys, and
emails you **only when a new key appears**. Most days: no email, nothing to do.

- Plain Ruby: Rack ingest endpoint + Sinatra GUI, SQLite, one YAML rules file.
- No JS build step, no framework, no external requests (fonts self-hosted).
- ~1,000 lines including tests. One person can hold the whole thing in their head.

## How it works

```
browser ──POST /csp──▶ ingest (public, write-only, always 204)
                          │  filter: schemes / hosts / structural checks
                          │    → dropped reports increment per-rule counters
                          ▼
                       SQLite: deduped keys with counts
                          ▲
        GUI /admin (auth) ─┘  browse, filter, "ignore" → appends rule, hot-reloaded
        digest (cron) ───▶ plain-text email, only when new keys appeared
```

**Filter classes** (checked in order, consolidated from Dropbox's CSP posts,
csp-wtf and friends):

1. **Schemes** — `chrome-extension:`, `moz-extension:`, etc. in blocked-uri or
   source-file. Kills all browser-extension noise.
2. **Host blocklist** — known injectors (translate.googleapis.com, antivirus
   proxies…). Grows from your live data via the GUI.
3. **Structural** — document-uri not on your domains (scanner bots POSTing
   directly), or a directive your policy doesn't emit (an extension/proxy
   rewrote your CSP header). Dropped.
4. **Unattributed inline** — inline/eval script violations with no source file.
   *Not* dropped: this is exactly what an injected-script attack looks like.
   Bucketed separately, deduped per script sample (enable `'report-sample'`
   in your policy), shown first in the digest.

**Ignore rules** are exact-match only (one host, one scheme, one sample) and
can only be created from a stored report — no free-text entry, so a click can
never create a rule broad enough to hide a real attack. Every rule shows a
drop counter so you can see what it eats.

**Flood safety:** 16KB body cap, per-POST report cap, max new keys per day
(excess collapses into one overflow row), max table size, 90-day prune.
Reports are counts, not rows — millions of reports stay thousands of rows.

**Privacy:** query strings and fragments are stripped before storage, client
IPs are never stored, everything prunes after `prune_days`.

## Quickstart

Requires Ruby 3.2+.

```sh
bin/setup        # bundle install, create config.yml with a fresh secret
$EDITOR config.yml
bin/test         # run the test suite

bundle exec puma -p 9292    # everything: POST /csp public, GUI at /admin
```

Point your site at it:

```
Content-Security-Policy: ...; report-uri https://csp.example.com/csp
Reporting-Endpoints: csp-endpoint="https://csp.example.com/csp"
Content-Security-Policy: ...; report-to csp-endpoint
```

Add `'report-sample'` to `script-src` so inline violations carry the first 40
chars of the script — that's what makes the unattributed-inline bucket useful.

## Configuration (config.yml)

| Key | What it does |
|---|---|
| `own_host_suffixes` | Domains you actually serve. Reports about any other document are dropped as scanner noise. Subdomains match automatically. |
| `policy_directives` | Directives your CSP actually emits. A report violating anything else means a proxy/extension rewrote your header — dropped. |
| `db_path` | SQLite file location (default `data/collector.sqlite3`). |
| `rules_path` | The live YAML ignore-rules file (default `data/rules.yml`; `bin/setup` seeds it from the tracked `rules.yml`). |
| `max_new_keys_per_day` | Flood cap: new dedupe keys per day before overflow (500 is generous). |
| `max_rows` | Hard cap on stored rows. |
| `session_secret` | GUI cookie secret — `bin/setup` generates one. |
| `digest.from` / `digest.to` / `digest.max_new_keys` | Digest sender, recipient, and how many new keys one email lists. |
| `smtp.*` | SMTP relay for the digest (host, port, optional starttls/user/password). |
| `title` | Shown in the GUI header and page title. |
| `prune_days` | Retention — rows unseen this long are deleted by the digest run. |

`rules.yml` can also be edited by hand (it hot-reloads). The `host_suffixes`
list (wildcard-ish suffix matching) is hand-edit only, by design.

There's no installer beyond `bin/setup` — one config file and one process
is the whole system.

## Deployment

Example units and Caddy config are in `deploy/`. The shape:

1. **App**: clone to `/opt/csp-collector`, create an unprivileged user, run
   `bin/setup`, edit `config.yml`.
2. **Service**: `deploy/csp-collector.service` runs puma on 127.0.0.1:9292 —
   one process serving both `POST /csp` (public) and `/admin` (basic auth via
   `gui_password`; `bin/setup` generates one, and `/admin` is not mounted at
   all if it's empty). Caddy (`deploy/Caddyfile.example`) terminates TLS for
   `csp.example.com` and enforces the body-size cap at the edge. Basic auth
   sends the password on every request, so HTTPS is mandatory. Optional
   hardening: Caddy `basic_auth` on `/admin` as a second layer, or a client-IP
   allowlist.
3. **Digest**: `deploy/csp-collector-digest.{service,timer}` (or a cron line:
   `0 6 * * * cd /opt/csp-collector && bundle exec bin/digest`). Also does
   the pruning.
4. **Deploys**: after the initial install, `bin/deploy` does everything —
   `git pull`, `bundle install`, service restart (needs one sudoers line,
   documented in the script). From your laptop it's a single command:
   `ssh <host> /opt/csp-collector/bin/deploy`.
5. **Backup**: the database is disposable (it's a rolling window); the live
   rules file (`data/rules.yml`) is the accumulated judgment — include it in
   your normal backups. The tracked `rules.yml` is only the seed, so deploys
   stay a plain `git pull && bundle install && systemctl restart` — nothing on
   the server ever modifies the checkout.

### Docker

A `Dockerfile` and `compose.yml` are included (pinned Ruby, two-stage build,
non-root, memory-capped):

```sh
cp config.yml.example config.yml   # edit; generate secrets with: openssl rand -hex 64
docker compose up -d --build       # app on 127.0.0.1:9292; data/ is created and
                                   # the rules file auto-seeds on first boot
```

Digest via host cron:
`0 6 * * * cd /path/to/app && docker compose exec -T app bundle exec bin/digest`.
Either path works — Docker or the bare-metal systemd units above; pick one.

Rate limiting: stock Caddy has no per-IP rate limiter (that's a plugin). At
typical volumes you don't need one — the body cap plus the new-key flood cap
bound the damage. Add the plugin if your threat model says otherwise.

## Security model

- `/csp` is public, unauthenticated (browsers can't send credentials), and
  treats every byte as hostile: size caps, always `204`, no reflection, and
  the collector never fetches anything.
- The GUI requires a password (`gui_password`, HTTP basic auth over HTTPS)
  plus sessions and CSRF tokens on every form. All GUI output is escaped;
  rule values are never taken from requests (only row IDs — values are
  re-extracted server-side and shape-validated).
- The rules file is written via `YAML.dump` of plain strings with flock +
  atomic rename, loaded with `safe_load` (no aliases), mode 0600.
- The collector going down cannot affect your site — reports are
  fire-and-forget from browsers.

## Development

```sh
bin/test                                      # test suite
bundle exec puma -p 9292   # then open http://127.0.0.1:9292/admin/
```


## License

[MIT](LICENSE). Bundled fonts (Instrument Sans, Fragment Mono) are
[SIL OFL 1.1](public/fonts/OFL.txt).
