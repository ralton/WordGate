#!/usr/bin/env python3
"""Source of truth for waf/rules/default.json.

Edit rules here (raw strings, no JSON escaping), then run:
    python3 tools/build-rules.py
"""
import json, os

STD = ["urldecode", "html_entity_decode", "remove_nulls", "lowercase", "compress_whitespace"]
SQL = ["urldecode", "remove_nulls", "remove_sql_comments", "lowercase", "compress_whitespace"]
PATH = ["urldecode", "remove_nulls", "normalize_path", "lowercase"]
PARAMS = ["query", "body", "cookies"]

rules = [
  # ---------------------------------------------------------------- SQL injection
  dict(id=1001, name="SQL injection: UNION-based", category="sqli", severity="critical",
       targets=PARAMS, transforms=SQL,
       pattern=r"\bunion(?: all| distinct)? ?\(? ?select\b.{0,120}?(?:\bfrom\b|\bnull\b|0x[0-9a-f]{2,}|@@\w+|\b(?:group_)?concat(?:_ws)?\s*\(|\bchar\s*\(|\bversion\s*\(|\buser\s*\(|\bdatabase\s*\(|(?:\b\d+ ?, ?){2})"),
  dict(id=1002, name="SQL injection: boolean tautology", category="sqli", severity="high",
       targets=PARAMS, transforms=SQL,
       pattern=r"(?:['\"`)]\s*(?:or|and|xor|\|\||&&)\s*\(?\s*['\"`]?[\w.-]+['\"`]?\s*(?:(?:=|<=>|!=|<>|\blike\b|\bregexp\b|\brlike\b)\s*['\"`]?[\w.-]+|[<>]=?\s*['\"`]?\d)|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|;|/\*|$)|['\"`]\s*(?:or|and)\s+(?:true|false|not\s+\w+)\s*(?:--|#|;|$))"),
  dict(id=1003, name="SQL injection: time-based blind", category="sqli", severity="critical",
       targets=PARAMS + ["headers"], transforms=SQL,
       pattern=r"(?:\bsleep\s*\(\s*\d+(?:\.\d+)?\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\bpg_sleep\s*\(|\bwaitfor\s+delay\s+['\"]|\bdbms_pipe\.receive_message\s*\()"),
  dict(id=1004, name="SQL injection: schema enumeration / file access / stacked query", category="sqli", severity="critical",
       targets=PARAMS, transforms=SQL,
       pattern=r"(?:\binformation_schema\s*\.|\bmysql\.(?:user|db)\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b|;\s*(?:drop|truncate|alter|create)\s+(?:table|database|user)\b|;\s*(?:insert\s+into|delete\s+from|update\s+[\w`]+\s+set)\b|\bsys\.(?:schema|user_summary)\b)"),
  dict(id=1005, name="SQL injection: error-based", category="sqli", severity="high",
       targets=PARAMS, transforms=SQL,
       pattern=r"(?:\b(?:extractvalue|updatexml)\s*\(|\bexp\s*\(\s*~\s*\(|\bgtid_subset\s*\(|\bjson_keys\s*\(\s*\(\s*select|\bpolygon\s*\(\s*\(\s*select|\bfloor\s*\(\s*rand\s*\(\s*\d*\s*\)\s*\*\s*2\s*\))"),
  dict(id=1006, name="SQL injection: syntax anomaly (SQL tokenizer)", category="sqli", severity="high",
       type="sqli", targets=PARAMS, transforms=["urldecode", "remove_nulls"],
       pattern=""),

  # ---------------------------------------------------------------- XSS
  dict(id=2001, name="XSS: script tag", category="xss", severity="high",
       targets=PARAMS + ["uri"], transforms=STD, admin_bypass=True,
       pattern=r"<\s*/?\s*script\b"),
  dict(id=2002, name="XSS: inline event handler", category="xss", severity="high",
       targets=PARAMS + ["uri"], transforms=STD, admin_bypass=True,
       pattern=r"<[a-z][^>]*?[\s/\"']on(?:abort|animation\w+|auxclick|beforeunload|blur|change|click|contextmenu|copy|cut|dblclick|drag\w*|drop|error|focus\w*|hashchange|input|invalid|key\w+|load\w*|message|mouse\w+|paste|pointer\w+|popstate|reset|resize|scroll|search|select\w*|submit|toggle|touch\w+|transition\w+|unload|wheel)\s*="),
  dict(id=2003, name="XSS: javascript/vbscript URI", category="xss", severity="high",
       targets=PARAMS, transforms=STD + ["remove_nulls"], admin_bypass=True,
       pattern=r"(?:^\s*|(?:href|src|action|formaction|data|xlink:href|srcdoc)\s*=\s*['\"]?\s*)(?:javascript|vbscript|livescript)\s*:|(?:href|src|action|formaction)\s*=\s*['\"]?\s*data\s*:\s*text/html"),
  dict(id=2004, name="XSS: dangerous HTML element", category="xss", severity="medium",
       targets=PARAMS, transforms=STD, admin_bypass=True,
       exclude_params=[r"content", r"post_content", r"excerpt", r"widget-.*", r"customized"],
       pattern=r"<\s*(?:iframe|frame|object|embed|applet|base\b|meta\b[^>]*http-equiv|svg\b[^>]*\bon\w+|math\b[^>]*xlink|form\b[^>]*action\s*=\s*['\"]?\s*https?:)"),
  dict(id=2005, name="XSS: JavaScript execution sinks", category="xss", severity="medium",
       targets=["query", "cookies", "uri"], transforms=STD,
       pattern=r"(?:\bdocument\s*\.\s*(?:cookie|write|domain)\b|\bwindow\s*\.\s*location\s*=|\b(?:alert|confirm|prompt)\s*\(\s*(?:document|1|['\"]?xss)|\bstring\.fromcharcode\s*\(|\beval\s*\(\s*(?:atob|unescape|string\.)|\bconstructor\s*\.\s*constructor\s*\()"),

  # ---------------------------------------------------------------- Path traversal / LFI
  dict(id=3001, name="Path traversal", category="lfi", severity="high",
       targets=PARAMS + ["uri"], transforms=PATH,
       pattern=r"(?:\.\./){3,}|(?:^|[/=])\.\./.*?(?:etc/(?:passwd|shadow|group|hosts)|proc/self/|wp-config\.php|\.htaccess|\.env\b|win\.ini|boot\.ini)"),
  dict(id=3002, name="Local file inclusion: sensitive file reference", category="lfi", severity="high",
       targets=["query", "cookies"], transforms=PATH,
       pattern=r"(?:^|/)(?:etc/(?:passwd|shadow)|proc/self/(?:environ|fd|cmdline)|wp-config\.php|c:/windows/win\.ini)\b"),
  dict(id=3003, name="Stream wrapper injection", category="lfi", severity="critical",
       targets=PARAMS, transforms=PATH,
       pattern=r"\b(?:php://(?:filter|input|fd|memory)|phar://|zip://|compress\.zlib://|expect://|glob://|data:(?://)?text/plain;base64,|file:///)"),
  dict(id=3004, name="Remote file inclusion", category="lfi", severity="high",
       targets=["query"], transforms=PATH,
       exclude_params=[r"redirect_to", r"url", r"_wp_http_referer", r"return_url", r"utm_.*", r"ref", r"fbclid", r"gclid"],
       pattern=r"^(?:https?|ftp)://[^?#]+\.(?:php\d?|phtml|txt|inc)\?*$"),

  # ---------------------------------------------------------------- Code / command injection
  dict(id=4001, name="PHP code injection", category="rce", severity="critical",
       targets=PARAMS + ["headers"], transforms=STD, admin_bypass=True,
       pattern=r"(?:<\?(?:php|=)?[\s\S]{0,200}?\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|base64_decode|file_put_contents|fwrite|include|require)\s*\(|\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|\$_(?:get|post|request|cookie|server))\b|\b(?:system|passthru|shell_exec|exec)\s*\(\s*\$_(?:get|post|request|cookie)\b)"),
  dict(id=4002, name="OS command injection", category="rce", severity="critical",
       targets=PARAMS + ["headers"], transforms=STD,
       pattern=r"(?:(?:[;&|`]|\$\()\s*(?:wget|curl)\s+(?:-\w+\s+)*(?:https?|ftp)://|(?:[;&|`]|\$\()\s*(?:/bin/|/usr/bin/)?(?:bash|sh|zsh|nc|ncat|netcat)\s+-[eic]|[;&|`]\s*cat\s+/etc/(?:passwd|shadow)|\$\(\s*(?:id|whoami|uname|cat|ls)\b[^)]*\)|`\s*(?:id|whoami|uname\s+-a)\s*`|;\s*(?:uname\s+-a|id|whoami)\s*(?:;|$)|\b(?:/bin/(?:ba)?sh|cmd\.exe\s+/c|powershell(?:\.exe)?\s+-(?:e|enc|nop))\b)"),
  dict(id=4003, name="PHP object injection (serialized object)", category="rce", severity="critical",
       targets=PARAMS, transforms=["urldecode", "remove_nulls"],
       pattern=r"(?:^|[;{}:])\s*[oc]:\+?\d+:\"[a-z_\\][\w\\]*\":\+?\d+:\{"),
  dict(id=4004, name="Server-side template / expression injection", category="rce", severity="high",
       targets=PARAMS + ["headers"], transforms=STD,
       pattern=r"\$\{\s*(?:jndi|env|sys|java|lower|upper|::-[a-z])\s*:|\{\{\s*(?:_self\.env|\[\s*['\"]id['\"]\s*\]\s*\|\s*filter|config\.items|request\.application)\b"),

  # ---------------------------------------------------------------- Uploads
  dict(id=5001, name="Upload: executable file extension", category="upload", severity="critical",
       targets=["files"], transforms=["remove_nulls", "lowercase"],
       pattern=r"\.(?:php\d?|phtml|phar|pht|phps|pgif|shtml|cgi|pl|py|asp|aspx|ashx|jsp|jspx)(?:\.|$|\s)|^\.(?:htaccess|user\.ini)$|\.htaccess$"),
  dict(id=5002, name="Upload: PHP code in file contents", category="upload", severity="critical",
       targets=["file_contents"], transforms=[], admin_bypass=True,
       pattern=r"<\?php|<\?=|<script\s+language\s*=\s*['\"]?php"),

  # ---------------------------------------------------------------- Scanners & probes
  dict(id=6001, name="Known attack tool user agent", category="scanner", severity="medium",
       targets=["user_agent"], transforms=["lowercase"],
       pattern=r"(?:sqlmap|nikto|wpscan|acunetix|nessus|openvas|masscan|zgrab|nuclei|dirbuster|gobuster|feroxbuster|ffuf|havij|w3af|netsparker|jaeles|fimap|commix|xsstrike|wfuzz|arachni|skipfish|whatweb|joomscan|hydra)"),
  dict(id=6002, name="Sensitive file probe", category="scanner", severity="medium",
       targets=["path"], transforms=PATH,
       pattern=r"(?:/\.(?:env(?:\.\w+)?|git/|svn/|hg/|ds_store|aws/|ssh/|bash_history)|/wp-config\.php(?:\.|~|_|-)\w*|/(?:wp-config|config|database|db|backup|dump|site)\.(?:sql|sql\.gz|zip|tar|tar\.gz|bak|old)$|/phpinfo\.php$|/(?:adminer|phpmyadmin)(?:[\d.-]*)\.php$|/composer\.(?:json|lock)$|/debug\.log$)"),
  dict(id=6003, name="Direct access to PHP file in uploads", category="scanner", severity="critical",
       targets=["path"], transforms=PATH,
       pattern=r"/wp-content/uploads/.*\.(?:php\d?|phtml|phar)$"),

  # ---------------------------------------------------------------- WordPress specific
  dict(id=7001, name="WordPress: privilege escalation via user meta", category="wordpress", severity="critical",
       targets=["query_keys", "body_keys"], transforms=["lowercase"], admin_bypass=True,
       pattern=r"(?:^|\[)(?:wp_capabilities|wp_user_level|wp_\d+_capabilities|\w+_capabilities)(?:\]|$)"),
  dict(id=7002, name="WordPress: XML-RPC multicall brute force", category="wordpress", severity="high",
       targets=["raw_body"], transforms=["lowercase"], paths=[r"/xmlrpc\.php(?:/|$)"],
       pattern=r"(?:(?:<name>\s*methodname\s*</name>\s*<value>\s*(?:<string>\s*)?|<methodname>\s*)(?:wp\.getusersblogs|wp\.getprofile|wp\.getoptions|blogger\.getusersblogs|metaweblog\.getusersblogs|wp\.getcategories)(?:\s*</string>)?\s*(?:</value>|</methodname>)[\s\S]{0,4096}?){3,}"),
  dict(id=7003, name="WordPress: XML-RPC pingback abuse (SSRF / DDoS)", category="wordpress", severity="medium", action="log",
       targets=["raw_body"], transforms=["lowercase"], paths=[r"/xmlrpc\.php(?:/|$)"],
       pattern=r"<methodname>\s*pingback\.ping\s*</methodname>[\s\S]*?(?:https?://(?:127\.|10\.|192\.168\.|169\.254\.|localhost|\[::1\]))"),
  dict(id=7004, name="WordPress: option update via unauthenticated AJAX", category="wordpress", severity="critical",
       targets=["body_keys", "query_keys"], transforms=["lowercase"], paths=[r"/wp-admin/admin-ajax\.php(?:/|$)", r"/wp-json/"], admin_bypass=True,
       pattern=r"^(?:users_can_register|default_role|siteurl|admin_email)$"),
]

seen = set()
for r in rules:
    assert r["id"] not in seen, r["id"]
    seen.add(r["id"])
    r.setdefault("action", "block")

out = {
  "schema": 1,
  "version": "2026.11.21",
  "description": "WordGate default WAF rules. Generated from tools/build-rules.py.",
  "rules": rules,
}
here = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(here, "..", "waf", "rules", "default.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
print(f"wrote {len(rules)} rules to {os.path.normpath(path)}")
