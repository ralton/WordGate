=== WordGate Security ===
Contributors: wordgate
Tags: security, firewall, malware scanner, two-factor authentication, brute force
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Open-source WordPress security: firewall, malware & integrity scanner, brute-force protection and two-factor authentication. No paid tiers, no account.

== Description ==

WordGate protects your site with:

* **Web application firewall** that runs before WordPress (via auto_prepend_file), blocking SQL injection, XSS, file inclusion, code injection, malicious uploads and scanners. Includes rate limiting, IP/CIDR blocking and learning mode.
* **Scanner**: core and plugin files checked against official wordpress.org checksums, known-vulnerability lookups, malware signatures, PHP in uploads, configuration checks, and one-click verified restore.
* **Login security**: brute-force lockouts enforced by the firewall, generic login errors, banned usernames.
* **Two-factor authentication**: TOTP with any authenticator app, recovery codes, and per-role enforcement.
* **Hardening**: XML-RPC control, user-enumeration blocking, security headers, file editor lock.

All rules and signatures are open source. No data leaves your site except checksum and vulnerability lookups (component slugs only, which can be disabled).

== Installation ==

1. Upload the `wordgate` folder to `/wp-content/plugins/` and activate it.
2. Go to WordGate → Firewall and set up extended protection.
3. Turn on 2FA from your profile page.
4. Run your first scan from WordGate → Scan.

== Frequently Asked Questions ==

= I locked myself out =

Create an empty file named `disable-waf` in `wp-content/wordgate/`, or run `wp wordgate unblock <ip>`. For 2FA, run `wp wordgate 2fa reset <user>`.

= My site is behind Cloudflare =

Set "Client IP comes from" to CF-Connecting-IP and add Cloudflare's IP ranges to "Trusted proxy IPs".

== Changelog ==

= 0.1.1 =
* New: read-only REST API (wordgate/v1) for remote diagnostics.
* New: "WordGate Auditor" role for use with application passwords.
* Activity log can be filtered by time (since).

= 0.1.0 =
* First release.
