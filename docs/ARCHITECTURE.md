# Architecture

WordGate is two programs that share state through files:

1. **The firewall** (`waf/`). Standalone PHP with no WordPress dependency. It runs on every request before WordPress, so it must be fast and must never need the database.
2. **The plugin** (`wordgate.php`, `includes/`). Runs inside WordPress: login security, scanner, admin UI, WP-CLI, and writing the firewall's configuration.

## Directory layout

```
waf/
  bootstrap.php        Entry point for auto_prepend_file / mu-plugin. Fails open on any error.
  src/Engine.php       Decision pipeline: allowlist → IP block → rate limit → rules.
  src/Rule.php         Declarative rule (targets, transforms, regex, path/method scope, exclusions).
  src/Transforms.php   Normalisation: urldecode×2, entities, SQL comments, path, case, whitespace.
  src/Request.php      Flattens the request into inspectable targets (query, body, cookies, headers,
                       *_keys, files, file_contents, raw_body, path, uri, user_agent).
  src/Storage.php      Data-directory I/O: config, blocks, counters, attack log, compiled rule cache.
  src/IpUtil.php       IPv4/IPv6 CIDR matching, spoof-resistant client IP resolution.
  rules/default.json   Generated from tools/build-rules.py.
includes/
  Plugin.php           Boots modules on plugins_loaded.
  Settings.php         One option, typed defaults, sanitisation; propagates to the WAF config.
  Installer.php        Tables, cron, activation/deactivation.
  Firewall/            WafConfig (settings → config.php), WafInstaller (mu-plugin / auto_prepend), 404 limiter.
  Login/               BruteForce, TwoFactor, Totp (RFC 6238), AdminCookie (signed WAF bypass).
  Scanner/             ScanRunner (resumable state machine), Issues, Signatures, Vulnerabilities, Repair.
  Hardening/           XML-RPC, enumeration, headers, file editor.
  Log/EventLog.php     Events table, WAF log ingestion, stats.
  Admin/               Screens and form handlers.
  Cli/Command.php      `wp wordgate …`
tools/                 Rule and signature sources (Python) → JSON.
tests/Unit/            PHPUnit; runs without WordPress.
```

## Data directory (`wp-content/wordgate/`)

| File | Writer | Reader | Notes |
|---|---|---|---|
| `config.php` | plugin | WAF | `return array(...)`, written atomically (temp + rename) and opcache-invalidated |
| `blocks.php` | plugin + WAF (rate limiter) | WAF + plugin | read-modify-write under `flock` |
| `rules.php` | WAF | WAF | compiled cache of `rules.json` / `default.json`, keyed by source path + mtime |
| `rules.json` | (future) rule feed updater | WAF | overrides the bundled rules when present |
| `signatures.json` | (future) feed updater | scanner | overrides the bundled signatures when present |
| `attack-log.jsonl` | WAF | plugin (hourly + on admin page view) | drained by atomic rename; capped at 20 MB |
| `counters/*.cnt` | WAF + plugin | same | fixed-window counters when APCu is unavailable |
| `disable-waf` | you | WAF | emergency kill switch |

The directory ships with `.htaccess`, `web.config` and `index.php` guards, and every generated PHP file exits unless loaded by WordGate.

## Request pipeline

1. **Allowlisted IP**: allow immediately.
2. **Blocked IP**: a `scope=login` block only applies to `wp-login.php` and `xmlrpc.php`. Blocks are enforced in learning mode too, because they are explicit admin intent.
3. **Rate limit**: per-IP fixed window; throttle (429) or temporary block.
4. **Rules**, in file order. For each target value: skip excluded/allowlisted parameters, apply the transform chain (memoised per request), then run the regex. The first `block` match wins. In learning mode, or for `log` rules, matches are only logged.

Rules flagged `admin_bypass` are skipped when the request carries a valid `wordgate_admin` cookie: `user_id|expiry|HMAC-SHA256(secret)`. The cookie is issued only to users with `unfiltered_html`, who WordPress already lets publish arbitrary HTML/JS, so the bypass grants nothing new. The secret lives only in the server-side config.

## Login and 2FA

- Brute-force failures are counted in the shared counters. A lockout writes a `scope=login` block, so after a lockout the WAF rejects attempts before WordPress boots, which saves CPU during an attack.
- 2FA intercepts `wp_login` (priority 1), clears the just-set auth cookie, and redirects to `wp-login.php?action=wordgate_2fa` with a random 256-bit token (stored hashed, 10-minute TTL, IP-bound, 5 attempts). After a valid code WordGate sets the auth cookie and re-fires `wp_login` so other plugins still see the login.
- TOTP verification accepts ±1 time step and stores the last used step, so a code can't be replayed.

## Scanner

A persisted state machine (`wordgate_scan_state` option). `step($budget)` runs phases until the time budget is spent; the admin UI polls via AJAX, cron chains single events, and WP-CLI loops.

`core → plugins → vulns → index → files → checks → finish`

Files whose checksum matched the official release are recorded as *verified* and skipped by the signature scan. Issues are keyed by a stable hash, so re-scans update rows, ignored issues stay ignored, and issues that disappear are resolved automatically.

## Design principles

- **Fail open.** Security software that takes sites down gets uninstalled. Every WAF path is wrapped, and on deactivation the prepend stub is neutered (not deleted) until PHP's `.user.ini` cache expires.
- **No lock-out footguns.** Lockouts are by IP, not username; you can't block your own IP from the UI; changing the IP source is refused when the header is absent; there are emergency switches for the WAF and for 2FA.
- **Everything inspectable.** Rules, signatures and data files are plain text, and there are no obfuscated payloads or remote code.
