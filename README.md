# WordGate

**Open-source security for WordPress.** A web application firewall, a malware and integrity scanner, brute-force protection, and two-factor authentication in one GPL plugin. There are no paid tiers, no account to create, and no phone-home.

WordGate covers the same core jobs as commercial WordPress security suites: it blocks attacks before WordPress loads, finds compromised files, and stops account takeover. Every rule, signature, and line of code is public, so you can audit it and improve it.

> **Status: 0.1.3 (early).** The core is functional and tested against WordPress 7.1, but it has not had broad production exposure yet. Run it in learning mode first on complex sites, and please report false positives.

---

## Features

### Web application firewall
- **Runs before WordPress.** *Extended* mode uses PHP's `auto_prepend_file`, so the firewall inspects every PHP request, including attacks aimed directly at a vulnerable plugin file, which never load WordPress at all. *Basic* mode runs as a must-use plugin and is set up automatically on activation.
- **27 open rules** covering SQL injection (union, boolean, time-based, error-based, stacked queries), XSS, path traversal and local/remote file inclusion, PHP and OS command injection, PHP object injection, malicious uploads, scanner probes, privilege escalation via user meta, and XML-RPC multicall brute force.
- **Normalisation before matching.** Double URL-encoding, HTML entities, SQL comments (`UNION/*...*/SELECT`, `/*!50000SELECT*/`), null bytes and case tricks are stripped before inspection.
- **Few false positives.** Every rule is tested against a corpus of ordinary traffic: comments containing "select" and "union", apostrophes, Markdown, JSON bodies, WooCommerce parameters, and so on. Logged-in users who can already publish unfiltered HTML get a signed, unforgeable cookie that skips HTML/JS-content rules.
- **Learning mode**, per-rule disabling, and a **targeted allowlist** (rule + URL path + parameter) that can be filled in with one click from the activity log.
- **Rate limiting** (throttle or block), **404-flood detection** for vulnerability scanners, and **IP / CIDR blocking** (IPv4 and IPv6), site-wide or login-only.
- **Spoof-resistant IP detection.** Proxy headers (`X-Forwarded-For`, `CF-Connecting-IP`, …) are trusted only when the request comes from a proxy you list.
- **Fails open.** A firewall bug must never take a site down, and there is a one-file emergency kill switch.

### Scanner
- **Core integrity**: every WordPress core file is compared against the official checksums from api.wordpress.org; unknown files in `wp-admin/`, `wp-includes/` and the site root are flagged.
- **Plugin integrity**: every wordpress.org plugin is compared against the official per-version checksums.
- **Known vulnerabilities**: installed plugin and theme versions are checked against the open [WPVulnerability](https://www.wpvulnerability.net/) database, which also flags plugins that have been closed or abandoned on wordpress.org. Severity comes from CVSS scores, and anything on CISA's known-exploited list is marked critical. Only component slugs are sent, never your URL.
- **Malware signatures**: 23 open signatures for web shells, eval/base64 droppers, request-driven code execution, backdoor admin creation, auth bypasses, obfuscation, JS skimmers, cryptominers and SEO spam. Files already verified by checksum are skipped, so scans are fast.
- **PHP files in uploads**, and configuration checks: pending core/plugin/theme updates, end-of-life PHP, debug output, a public `debug.log`, an `admin` username, a world-readable `wp-config.php`, no HTTPS, and admins without 2FA.
- **One-click repair**: restore an original core or plugin file (downloaded from the official SVN and **verified against the checksum before writing**), or delete a malicious file.
- **Resumable and time-boxed**, so it finishes on cheap shared hosting. Runs daily or weekly, or on demand.

### Login security
- **Brute-force lockouts** per IP, enforced by the firewall before WordPress loads. Lockouts are per IP, never per username, so an attacker cannot lock the real admin out.
- **Instant lockout** for banned usernames (`admin`, `root`, …) that don't exist on the site; optional instant lockout for any unknown username.
- **Generic login errors**, so attackers can't tell whether a username exists.
- **Two-factor authentication (TOTP)** with any authenticator app. The QR code is generated locally, never by a third-party service. Ten single-use recovery codes, replay protection, a separate code-entry step, and 2FA can be **required per role** with a grace period. Password-only XML-RPC/REST logins are refused for 2FA users; application passwords still work.

### Hardening
Toggles to disable XML-RPC (fully, or just logins), block `?author=N` username discovery, hide `/wp/v2/users` from anonymous visitors, remove the WordPress version, disable the theme/plugin file editor, and send security headers (HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy).

### Operations
- Dashboard, activity log with filters, email alerts (rate-limited), and a [WP-CLI](#wp-cli) interface for everything.
- No external services are required. WordPress.org (checksums) and WPVulnerability (optional) are the only outbound calls.

---

## Install

**From source (for now):**

```bash
cd wp-content/plugins
git clone https://github.com/ralton/wordgate.git
```

Then activate **WordGate Security** in *Plugins*. On activation WordGate creates `wp-content/wordgate/` (protected against web access), installs the basic firewall loader into `mu-plugins/`, and schedules daily scans.

**Recommended next steps:**
1. *WordGate → Firewall → Upgrade to extended protection*. Pick your server type; it's auto-detected.
2. *Users → Profile → Two-factor authentication*. Turn on 2FA for your own account.
3. *WordGate → Login Security*. Require 2FA for administrators.
4. *WordGate → Scan → Start scan*.

**If you're behind Cloudflare or another proxy**, set *Firewall → Client IP comes from* and list the proxy's IP ranges under *Trusted proxy IPs*. Otherwise every visitor appears to come from the proxy.

### Requirements
PHP 7.4+ (8.2+ recommended) and WordPress 6.0+. APCu is used for rate-limit counters when available; otherwise counters are stored in files.

### Emergency access
| Problem | Fix |
|---|---|
| Firewall blocking you | Create an empty file `wp-content/wordgate/disable-waf`, or add `define( 'WORDGATE_WAF_DISABLE', true );` to `wp-config.php` |
| Locked out of login | `wp wordgate unblock <your-ip>`, or delete the entry from `wp-content/wordgate/blocks.php` |
| Lost 2FA phone and codes | `wp wordgate 2fa reset <user>`, or temporarily add `define( 'WORDGATE_DISABLE_2FA', true );` |

---

## WP-CLI

```bash
wp wordgate scan                       # full scan, prints issues
wp wordgate issues --status=open --format=json
wp wordgate block 203.0.113.0/24 --minutes=1440 --reason="botnet"
wp wordgate block 198.51.100.7 --login-only
wp wordgate unblock 203.0.113.0/24
wp wordgate blocks
wp wordgate waf status                 # mode, protection level, rules, blocks
wp wordgate waf learning               # enable | learning | disable
wp wordgate waf install-extended --server=user-ini
wp wordgate 2fa status
wp wordgate 2fa reset jane
```

---

## How it works

```
 Request ──▶ auto_prepend_file (extended) or mu-plugin (basic)
               │
               ▼
          waf/bootstrap.php  ── no WordPress, no database; reads opcache-cached PHP files
               │   allowlist → IP block → rate limit → rules
               ├──▶ 403 / 429 block page   (event appended to attack-log.jsonl)
               ▼
          WordPress loads ──▶ WordGate plugin
                               ├─ login security & 2FA ── writes lockouts to blocks.php
                               ├─ scanner (resumable)  ── wordgate_issues table
                               ├─ activity log         ── ingests attack-log.jsonl → wordgate_events table
                               └─ admin UI / WP-CLI    ── writes config.php for the firewall
```

The firewall and the plugin share state through files in `wp-content/wordgate/`, so the firewall never needs a database connection. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Development

```bash
composer install
composer test                 # 123 unit tests: WAF engine + rules, TOTP (RFC 6238 vectors), IP utils, signatures
python3 tools/build-rules.py        # regenerate waf/rules/default.json
python3 tools/build-signatures.py   # regenerate includes/Scanner/signatures.json
```

Rules and signatures are written as readable Python raw strings in `tools/` and compiled to JSON. **Every new rule needs a test that it blocks the attack and a test that it doesn't block similar legitimate traffic.** See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap
See [docs/ROADMAP.md](docs/ROADMAP.md). Highlights: a signed community rule feed with automatic updates, country blocking, a live traffic view, a login reCAPTCHA/Turnstile option, WebAuthn passkeys, and multisite support.

## Security
Found a vulnerability in WordGate itself? Please report it privately. See [SECURITY.md](SECURITY.md).

## License
GPL-2.0-or-later. Bundles [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT) for local QR rendering.
