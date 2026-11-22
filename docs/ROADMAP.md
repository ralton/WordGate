# Roadmap

## Where WordGate stands

Commercial WordPress security suites have three layers of value:

| Layer | Commercial suites | WordGate 0.1 |
|---|---|---|
| **Engine**: WAF, scanner, 2FA, lockouts | Mature | ✅ Functional core |
| **Threat intelligence**: rules for new vulnerabilities, malware signatures, IP reputation | Proprietary, often delayed 30 days for free users | ⚠️ Static bundled rules and signatures; open vulnerability data via WPVulnerability |
| **Services**: incident response, site cleaning, support | Paid | ❌ |

Most of the lasting value, and the moat, is layer 2. An open-source alternative becomes compelling when it has an **open, community-maintained, real-time threat feed**. That is the main item on this roadmap.

Priorities below come from a source-level comparison with Wordfence 9.1.1. See [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md).

## 0.2: Credibility (close the gaps that matter most)
- [ ] **Signed rule and signature feed.** Ed25519-signed bundles from GitHub Releases, verified with `sodium_crypto_sign_verify_detached`, daily auto-update with rollback. Same speed for everyone: no free-tier delay.
- [ ] **SQL tokenizer** (libinjection-style fingerprinting) to replace the regex SQLi rules: fewer false positives, catches obfuscation.
- [ ] **Database content scan**: posts, comments and options for injected scripts, iframes, spam links and a tampered `siteurl`/`home`.
- [ ] **Suspicious admin detection**: admins created since the last scan or outside wp-admin.
- [ ] **Tamper alerts**: WordGate deactivated, WAF loader removed, admin user created, security settings changed.
- [ ] Rate-limit password-reset requests.
- [ ] Breached-password check (HIBP k-anonymity) plus a bundled common-password list; optional enforcement by role.
- [ ] Disable PHP execution in uploads (`.htaccess` / nginx snippet).

## 0.3: Parity users notice (and what Wordfence charges for, free)
- [ ] **Country blocking**, free (DB-IP Lite, CC BY 4.0), with a bypass URL/cookie.
- [ ] **Audit log**, free: content, user, plugin and setting changes.
- [ ] Live traffic view (opt-in sampling).
- [ ] Cloudflare Turnstile / hCaptcha on login, registration and password reset.
- [ ] Passkeys (WebAuthn); "remember this device"; WooCommerce login and account 2FA; NTP time correction for TOTP.
- [ ] Separate human/crawler rate limits; forward-confirmed reverse-DNS verification of search crawlers; allowed-404 list.
- [ ] Pattern blocks (hostname, user agent, referrer); banned URLs.
- [ ] Automatic IP-source / proxy misconfiguration detection.
- [ ] Scanner: theme integrity, directory listing, full-path disclosure, exposed config backups, weak user passwords.
- [ ] Local settings import/export (JSON + WP-CLI); weekly summary email; "new device" admin login alerts.

## 0.4: Beyond
- [ ] **Universal file-integrity baseline**: hash every file (premium plugins, custom themes, mu-plugins) and alert on unexpected change, trusting changes made by WordPress updates.
- [ ] **Quarantine** instead of delete, with one-click restore.
- [ ] **Automatic virtual patching**: draft path/parameter-scoped rules from public advisories, reviewed by a maintainer, signed, and enabled only on sites running the vulnerable version.
- [ ] **Edge sync**: push blocks and country rules to Cloudflare so attacks never reach PHP.
- [ ] Honeypots: decoy form fields, canary admin account, decoy login paths.

## 0.5: Scale
- [ ] Opt-in, privacy-preserving community reputation network (HMAC-truncated prefixes, no URLs or site names).
- [ ] Self-hostable fleet dashboard for agencies.
- [ ] Security as code (`wordgate.json`, drift detection), webhooks, SIEM/syslog output, REST API.
- [ ] Multisite; MySQL storage fallback for the WAF.
- [ ] Optional AI-assisted triage (bring your own key, advisory only).

## Sustainability options (to decide)
The plugin stays 100% GPL and fully functional. Possible ways to fund maintenance without crippling it:
- **Hosted feed SLA**: rules stay free, but organisations can sponsor faster review or a support contract.
- **Managed fleet dashboard** (hosted version of the self-hostable one) for agencies.
- **Incident response / cleanup** as a service.
- GitHub Sponsors / Open Collective.
