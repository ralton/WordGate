# Security policy

## Reporting a vulnerability in WordGate

Please **do not open a public issue**. Report privately through GitHub's
[private vulnerability reporting](https://github.com/ralton/wordgate/security/advisories/new).

Include affected versions, reproduction steps, and impact. We aim to acknowledge reports within 3 business days and to ship a fix for critical issues within 14 days, then credit you in the advisory (unless you prefer otherwise).

## Scope

In scope: WAF bypasses that affect the default ruleset in a way the rule was intended to catch, authentication and 2FA bypasses, privilege escalation, file read/write or deletion, XSS/CSRF in the admin UI, and anything that lets an attacker disable protection.

Out of scope: attacks that require an administrator account (administrators can already run arbitrary code in WordPress), missing rules for new attack classes (please open a normal issue or PR), and denial of service through traffic volume.

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.
