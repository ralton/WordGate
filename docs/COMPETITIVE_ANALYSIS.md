# WordGate vs Wordfence: feature analysis

*Based on a source review of Wordfence 9.1.1 (wordpress.org release, downloaded 2026-11-22) and WordGate 0.1.0. No Wordfence code was copied; this document records features and design choices only.*

## Summary

Wordfence is a mature, broad product: 638 files, 17 MB, and about 160 settings. Its real advantages are **threat intelligence that updates continuously**, a **SQL-syntax-aware injection detector**, and **breadth**: database content scanning, passkeys, CAPTCHA, live traffic, an audit log and fleet management.

Its weaknesses are a business model that **holds back protection for free users**, and an architecture that **depends on Wordfence's servers and shares site data with them by default**. Those are the openings for WordGate.

| | Wordfence (free) | Wordfence (paid) | WordGate 0.1 |
|---|---|---|---|
| Firewall rule updates | Weekly (`86400 * 7` in code); vendor publicly states new rules reach free users after 30 days | Every 12 h | Static bundle (no feed yet) |
| Malware signature updates | Every ~3 days | Every 12 h | Static bundle |
| Country blocking | ❌ Paid only (`wfBlock::TYPE_COUNTRY` checks `isPaid`, even though the country database ships in the free plugin) | ✅ | ❌ |
| Audit log | Preview only (`wfAuditLog::mode()`) | ✅ | Partial (security events only) |
| Real-time IP blocklist | ❌ | ✅ | ❌ |
| Rules inspectable by site owner | ❌ Downloaded compiled and signed | ❌ | ✅ Plain JSON in the repo |
| Works with no vendor account or connection | ❌ Requests an API key (`get_anon_api_key`) and agreement to terms | ❌ | ✅ |
| Data sent off-site by default | Attack data incl. site URL (`send_waf_attack_data`), failed-login IPs (`other_WFNet` defaults on), file hashes (`is_safe_file`), URLs found in content (`check_bad_urls`), scan metrics | Same | Component slugs only (vulnerability lookup; can be disabled) |

---

## Feature-by-feature

✅ = has it · ◐ = partial · ❌ = missing

### Firewall

| Capability | WF | WG | Notes / opportunity |
|---|---|---|---|
| Runs before WordPress (`auto_prepend_file`) | ✅ | ✅ | Parity. Both neuter the stub on removal to survive `.user.ini` caching. |
| Signed rule updates | ✅ | ❌ | **P0.** WF verifies with a bundled key (`rules.key`). WG: Ed25519 via libsodium, same for everyone, no delay. |
| SQL-aware SQLi detection | ✅ ~5,800-line lexer/parser (`parser/sqli*.php`) | ❌ Regex | **P0.** Biggest quality gap. A tokenizer gives far fewer false positives and catches obfuscated SQLi that regex misses. Write our own (libinjection-style fingerprinting). |
| Learning mode | ✅ | ✅ | Parity. |
| Allowlist a false positive per rule/path/param | ✅ | ✅ | WF also sends false positives home (`send_waf_false_positives`). WG could offer *opt-in* reporting. |
| Rate limits split by humans vs crawlers | ✅ (`maxRequestsHumans`, `maxRequestsCrawlers`, `max404*`) | ◐ One limit | P1. |
| Verified-crawler bypass (reverse-DNS Googlebot/Bingbot) | ✅ (`neverBlockVerified`, `verify_googlebot` via their API) | ❌ | P1. Do forward-confirmed reverse DNS locally, with no API needed. |
| Allowed-404 list (favicon, apple-touch-icon…) | ✅ | ❌ | P1, small. |
| Auto-block vulnerability scanners | ✅ | ✅ | Parity (UA rule + 404 limiter). |
| Ban URL patterns (instant block) | ✅ (`bannedURLs`) | ❌ | P2. |
| Pattern blocks (IP range + hostname + UA + referrer) | ✅ Free | ◐ IP/CIDR only | P1. |
| Country blocking (with bypass URL/cookie) | 💰 Paid | ❌ | **P1, and free in WG.** Use DB-IP Lite (CC BY 4.0, bundling allowed). |
| Real-time IP reputation feed | 💰 Paid | ❌ | P2. Community-sourced, opt-in, privacy-preserving (see "Go beyond"). |
| Storage fallback to MySQL | ✅ | ❌ | P2, for hosts where `wp-content` isn't writable. |
| Block-page customisation / unlock-by-email | ✅ | ◐ | P2. Self-unlock by email link is valuable for lockouts. |

### Login security

| Capability | WF | WG | Notes |
|---|---|---|---|
| Brute-force lockout | ✅ (default 20 failures in 4 h) | ✅ (default 5 in 15 min) | Parity. WG enforces at the WAF layer before WordPress loads. |
| Limit password-reset requests | ✅ (`maxForgotPasswd`) | ❌ | **P0, small.** Reset flooding harasses admins and leaks valid emails. |
| Mask login errors / block author scans | ✅ | ✅ | Parity. |
| Block admin registration | ✅ (`blockAdminReg`) | ◐ WAF rule 7004 only | P1. Hook `user_register` and refuse admin roles without `promote_users`. |
| Disable application passwords | ✅ | ❌ | P1, small toggle. |
| Weak / breached password enforcement | ✅ (local common-password list + breach check via their API) | ❌ | **P0.** Use HIBP's k-anonymity API (only a 5-char hash prefix leaves the site) plus a bundled common-password list. |
| TOTP 2FA + recovery codes + role requirement + grace period | ✅ | ✅ | Parity. |
| **Passkeys / WebAuthn** | ✅ (new) | ❌ | **P1.** |
| Remember device for N days | ✅ | ❌ | P1. Big usability win that keeps 2FA turned on. |
| NTP time-sync for TOTP | ✅ | ❌ | P2. Fixes "code always invalid" on servers with drifting clocks. |
| CAPTCHA on login/registration | ✅ reCAPTCHA v3 | ❌ | P1. Use **Cloudflare Turnstile** (privacy-friendly) with an hCaptcha option. |
| WooCommerce login/account 2FA, shortcode | ✅ | ❌ | P1. WooCommerce is a huge share of the market. |
| 2FA on XML-RPC | ✅ (option) | ◐ Refuses password-only | Parity in effect. |
| Login history columns in Users list | ✅ | ❌ | P2, small. |

### Scanner

| Capability | WF | WG | Notes |
|---|---|---|---|
| Core integrity vs official checksums | ✅ | ✅ | Parity. |
| Plugin integrity vs official checksums | ✅ (off by default!) | ✅ (on) | WG ahead by default. |
| Theme integrity | ✅ (off by default) | ❌ | P1. |
| Unknown files in core dirs | ✅ | ✅ | Parity. |
| Malware signatures | ✅ Large commercial set, plus a remote hash check (`is_safe_file`) | ◐ 23 open signatures | Gap closes only with the feed and community growth. |
| Known vulnerabilities (plugins/themes/core) | ✅ Via their API | ✅ Via open WPVulnerability (with CISA known-exploited flagging) | Parity; WG is open data. |
| Abandoned/closed plugins | ✅ | ✅ | Parity. |
| **Database content scan** (posts, comments, options) for injected scripts, spam links, iframes | ✅ | ❌ | **P0.** Most real-world infections (SEO spam, JS redirects) live in the database, not in files. |
| Malicious URLs in content (Safe Browsing) | ✅ Via their API | ❌ | P1. Could use Google Safe Browsing v4 with the user's own key, or URLhaus/PhishTank feeds locally. |
| Suspicious admin users | ✅ | ❌ | **P0.** Flag admins created since the last scan, created outside wp-admin, or with known-bad usernames. |
| Suspicious options (injected `siteurl`, malicious widgets) | ✅ | ❌ | P0 (part of the database scan). |
| Weak passwords of existing users | ✅ | ❌ | P1 (pairs with the password policy). |
| Directory listing enabled / full-path disclosure | ✅ | ❌ | P1, small HTTP self-checks. |
| Readable config backups (`wp-config.php.bak`) | ✅ | ◐ WAF blocks them; scanner doesn't report them | P1, small. |
| Disk space / skipped files report | ✅ | ❌ | P2. |
| IP detection misconfiguration check | ✅ (`checkHowGetIPs`) | ◐ UI hint only | **P1.** A wrong setting either blocks everyone or makes the WAF blind. Auto-detect it. |
| Scan types (limited / standard / high sensitivity) | ✅ | ❌ | P2. |
| Low-resource scanning, resume attempts | ✅ | ✅ Time-boxed and resumable | Parity. |
| Repair / restore / delete | ✅ | ✅ Checksum-verified before writing | Parity. |
| Quarantine | ❌ | ❌ | **Go-beyond** (see below). |

### Visibility, operations, alerts

| Capability | WF | WG | Notes |
|---|---|---|---|
| Live traffic view | ✅ Free | ❌ | P1. |
| Audit log (content/user/settings changes) | 💰 Paid | ❌ | **P1, free in WG.** |
| Alert: security plugin or WAF deactivated | ✅ | ❌ | **P0, small.** Attackers' first move is to switch off security plugins. |
| Alerts: admin login, first login from new device, lockout, block threshold, updates | ✅ | ◐ | P1. Add "new device/IP for this admin" rather than every login. |
| Weekly summary email | ✅ | ❌ | P1. |
| Import/export settings | ✅ (via their servers) | ❌ | P1. Do it locally (JSON + WP-CLI). |
| Fleet management | ✅ Wordfence Central (their cloud) | ❌ | Go-beyond: self-hostable. |
| WP-CLI | ◐ Limited (login security) | ✅ Full | **WG ahead.** |
| Disable PHP execution in uploads (`.htaccess`) | ✅ | ❌ | P1, small. |
| Multisite | ✅ | ❌ | P2. |
| Auto-update of the security plugin itself | ✅ | ❌ | P2. |

---

## Where WordGate already leads

1. **No paywall on protection.** Country blocking, the audit log and real-time rule updates will be free.
2. **Open, auditable rules and signatures**, with tests that prove each rule both blocks its attack and allows similar legitimate traffic.
3. **Privacy by default.** Nothing about your traffic, users or files leaves the site, and no account is needed.
4. **Plugin integrity checks are on by default**; Wordfence ships them off.
5. **Full WP-CLI** for automation and agencies.
6. **Small footprint**: about 60 files.
7. **Fewer lockout footguns**: you can't block your own IP, IP-source changes are validated, and both the WAF and 2FA have emergency switches.

## Go beyond: things Wordfence doesn't do

These are the differentiators worth building a brand on.

1. **Zero-delay open threat feed.** Every site gets every rule as soon as it's reviewed, signed with Ed25519, and published only after CI proves it against attack and benign corpora. That turns Wordfence's free-tier delay into WordGate's headline.
2. **Automatic virtual patching from public advisories.** When WPVulnerability or a CVE feed publishes a plugin vulnerability, generate a draft path- and parameter-scoped rule, have a maintainer review it, and ship it signed. Sites running a vulnerable plugin version get the rule enabled automatically, *only for that plugin*. That's precise, with near-zero false-positive risk.
3. **File integrity monitoring for everything.** Wordfence can only verify wordpress.org code. WordGate can take a hash baseline of *all* files on first scan (premium plugins, custom themes, mu-plugins) and alert on any unexpected change. Pair it with a "trust this update" flow when plugins update through WordPress itself.
4. **Quarantine instead of delete.** Move suspicious files to an encrypted, non-executable quarantine with one-click restore, so cleanup is reversible.
5. **Privacy-preserving community intelligence (opt-in).** Share attack sightings as `(rule_id, HMAC-truncated /24 prefix, hour)` and publish an aggregated reputation list. You get community protection without sending URLs, site names or raw IPs. Make it GDPR-explainable in one sentence.
6. **Edge offload.** Push blocks and country rules to Cloudflare (or another WAF) through their API, so attacks are stopped before they reach PHP at all. Wordfence can't do this because it's PHP-only.
7. **Deception.** Honeypot form fields, canary admin accounts and decoy `wp-login` paths that instantly block anyone who touches them. Very low false-positive signal.
8. **Security as code.** `wordgate.json` in the repo or via `wp-config` constants, with config-drift detection and GitOps-friendly agency rollout. Also webhooks, SIEM/syslog JSON output, and a documented REST API.
9. **Self-hostable fleet dashboard.** Agencies keep their clients' data on their own infrastructure.
10. **AI-assisted triage (optional, bring your own key).** Explain a flagged file in plain language, highlight what changed versus the official version, and draft an allowlist entry from a false-positive log. Keep it advisory, never auto-acting, and never on by default.

## Recommended sequence

- **0.2: credibility.** Signed rule and signature feed, SQL tokenizer, database content scan, suspicious-admin detection, deactivation and tamper alerts, password-reset limiting, breached-password check, uploads PHP-execution lockdown.
- **0.3: parity users notice.** Country blocking (free), live traffic, audit log (free), Turnstile CAPTCHA, remember-device, passkeys, WooCommerce 2FA, human/crawler rate limits with verified crawlers, IP-detection auto-check, import/export.
- **0.4: beyond.** Universal file-integrity baseline, quarantine, auto virtual patching, Cloudflare edge sync, honeypots.
- **0.5: scale.** Opt-in community reputation network, self-hosted fleet dashboard, multisite, security-as-code, AI triage.
