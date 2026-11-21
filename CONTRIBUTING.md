# Contributing to WordGate

Thanks for helping make WordPress safer.

## Setup

```bash
git clone https://github.com/ralton/wordgate.git
cd wordgate
composer install
composer test
```

The unit tests run without WordPress. For manual testing, symlink the repo into `wp-content/plugins/wordgate` on a local WordPress install (wp-env, LocalWP, DDEV and Docker all work).

## Firewall rules

Rules live in `tools/build-rules.py` as Python raw strings (no JSON escaping). After editing:

```bash
python3 tools/build-rules.py
composer test
```

Every rule change must include:

1. **Attack tests** in `EngineTest::maliciousProvider()` showing the payloads it blocks, including at least one evasion (encoding, comments, case).
2. **Benign tests** in `EngineTest::benignProvider()` showing realistic traffic it must *not* block. False positives are bugs, and they get the plugin uninstalled.

Guidelines:
- Be specific. Prefer matching attack *syntax* (`union select … from`) over attack *words*.
- Scope with `paths`, `methods`, `targets` and `exclude_params` wherever possible.
- Mark rules that match HTML or JS in content with `admin_bypass: true`.
- Use `"action": "log"` for new rules you're unsure about; they can be promoted later.
- IDs: 1xxx SQLi, 2xxx XSS, 3xxx LFI/RFI, 4xxx RCE, 5xxx uploads, 6xxx scanners, 7xxx WordPress-specific, 8xxx plugin-specific virtual patches.

## Malware signatures

Signatures live in `tools/build-signatures.py`. Add a detection test **and** a clean-code test to `SignaturesTest`. Never commit live malware samples; use minimal reproductions of the pattern.

## Code style

WordPress Coding Standards for the plugin, PHP 7.4 compatible. The `waf/` directory must not call any WordPress function.

## Pull requests

- One logical change per PR, with tests.
- Describe how you tested it (unit tests and/or a real site).
- Security-sensitive changes (auth, 2FA, file writes, the WAF bypass cookie) get extra review.
