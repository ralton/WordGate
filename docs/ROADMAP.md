# Roadmap

## Where WordGate stands

Commercial WordPress security suites have three layers of value:

| Layer | Commercial suites | WordGate 0.1 |
|---|---|---|
| **Engine**: WAF, scanner, 2FA, lockouts | Mature | ✅ Functional core |
| **Threat intelligence**: rules for new vulnerabilities, malware signatures, IP reputation | Proprietary, often delayed 30 days for free users | ⚠️ Static bundled rules and signatures; open vulnerability data via WPVulnerability |
| **Services**: incident response, site cleaning, support | Paid | ❌ |

Most of the lasting value, and the moat, is layer 2. An open-source alternative becomes compelling when it has an **open, community-maintained, real-time threat feed**. That is the main item on this roadmap.

## 0.2: Open threat feed
- [ ] Signed rule and signature bundles published from this repo (GitHub Releases), verified with an Ed25519 public key shipped in the plugin (`sodium_crypto_sign_verify_detached`) before being written to `wordgate/rules.json` and `signatures.json`.
- [ ] Daily auto-update with rollback if the new bundle fails to compile or validate.
- [ ] Rule tests run in CI against an attack corpus and a benign corpus; a bundle is only published if both pass.
- [ ] "Virtual patch" rules: path- and parameter-scoped rules for specific plugin CVEs, generated from public advisories.

## 0.3: Visibility
- [ ] Live traffic view (opt-in sampling of all requests, with bots and humans separated).
- [ ] Country blocking (user-supplied MaxMind GeoLite2 or DB-IP Lite database).
- [ ] Optional login CAPTCHA (Cloudflare Turnstile / hCaptcha) after N failures.
- [ ] Slack and webhook alerts.

## 0.4: Accounts
- [ ] WebAuthn / passkeys as a second factor.
- [ ] Session management: view and revoke sessions, idle timeout, concurrent-session limit.
- [ ] Password policy: breached-password check via HIBP k-anonymity, minimum strength.

## 0.5: Scale
- [ ] Multisite (network admin, per-site logs).
- [ ] Theme checksums for wordpress.org themes (no official API yet; compute from the SVN zip).
- [ ] Fleet mode: an optional, self-hostable central dashboard for agencies (opt-in reporting to *your* server).
- [ ] Quarantine instead of delete for malware removal.

## Sustainability options (to decide)
The plugin stays 100% GPL and fully functional. Possible ways to fund maintenance without crippling it:
- **Hosted feed SLA**: rules stay free, but organisations can sponsor faster review or a support contract.
- **Managed fleet dashboard** (hosted version of the self-hostable one) for agencies.
- **Incident response / cleanup** as a service.
- GitHub Sponsors / Open Collective.
