#!/usr/bin/env python3
"""Source of truth for includes/Scanner/signatures.json (malware patterns).

Patterns are PCRE (no delimiters) compiled case-insensitively. Keep them
specific: every false positive costs a site owner time and trust.
    python3 tools/build-signatures.py
"""
import json, os

PHP = ["php", "phtml", "php5", "php7", "phar", "inc", "pht", "phps"]
WEB = PHP + ["js", "html", "htm", "svg"]
ANY = PHP + ["js", "html", "htm", "svg", "ico", "jpg", "jpeg", "png", "gif", "txt", "suspected", "bak", "zip"]

sigs = [
  dict(id="PHP.Eval.Base64", name="eval() of base64-decoded data", severity="critical", types=PHP,
       pattern=r"\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin)\s*\("),
  dict(id="PHP.Eval.Request", name="eval()/assert() of request data", severity="critical", types=PHP,
       pattern=r"\b(?:eval|assert|create_function)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"),
  dict(id="PHP.Exec.Request", name="Shell execution of request data", severity="critical", types=PHP,
       pattern=r"\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*|base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"),
  dict(id="PHP.Backtick.Request", name="Backtick shell execution of request data", severity="critical", types=PHP,
       pattern=r"`\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\["),
  dict(id="PHP.PregReplace.Eval", name="preg_replace with /e modifier", severity="critical", types=PHP,
       pattern=r"\bpreg_replace\s*\(\s*['\"]([^\w\s\\])(?:(?!\1).)*\1[imsxuADSUX]*e[imsxuADSUX]*['\"]"),
  dict(id="PHP.VariableFunction.Request", name="Variable function called from request data", severity="critical", types=PHP,
       pattern=r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?\w*['\"]?\s*\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
  dict(id="PHP.Include.Request", name="Include of request-controlled path", severity="high", types=PHP,
       pattern=r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\["),
  dict(id="PHP.FileWrite.Request", name="Writes request data to a file", severity="high", types=PHP,
       pattern=r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^;]{0,80}\$_(?:GET|POST|REQUEST|COOKIE)\s*\["),
  dict(id="PHP.Upload.Unrestricted", name="Unrestricted file uploader", severity="high", types=PHP,
       pattern=r"move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]tmp_name['\"]\s*\]\s*,\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]\s*\)"),
  dict(id="PHP.Obfuscation.CharChain", name="Function name built from chr()/character concatenation", severity="high", types=PHP,
       pattern=r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}"),
  dict(id="PHP.Obfuscation.HexString", name="Long hex-escaped string (common obfuscation)", severity="medium", types=PHP,
       pattern=r"(?:\\x[0-9a-f]{2}){40,}"),
  dict(id="PHP.Obfuscation.GlobalsArray", name="Obfuscated $GLOBALS function dispatch", severity="high", types=PHP,
       pattern=r"\$GLOBALS\s*\[\s*['\"][^'\"]{1,40}['\"]\s*\]\s*\[\s*\d+\s*\]\s*\(\s*\$GLOBALS\s*\[\s*['\"][^'\"]{1,40}['\"]\s*\]\s*\[\s*\d+\s*\]"),
  dict(id="PHP.Obfuscation.LongBase64Eval", name="Large base64 blob passed to decoder", severity="medium", types=PHP,
       pattern=r"(?:base64_decode|gzinflate|str_rot13)\s*\(\s*['\"][a-z0-9+/=]{2000,}['\"]"),
  dict(id="PHP.Obfuscation.Goto", name="Goto-spaghetti obfuscation", severity="medium", types=PHP,
       pattern=r"(?:\bgoto\s+[a-z0-9_]{4,}\s*;\s*[a-z0-9_]{4,}\s*:\s*){10,}"),
  dict(id="PHP.Webshell.Markers", name="Known web shell signature", severity="critical", types=ANY,
       pattern=r"(?:FilesMan|WSO\s+[\d.]+|b374k|c99shell|r57shell|IndoXploit|Uname:\s*<|safe_mode\s*:\s*<b>|\bAnonSec\b|mini\s*shell\s*by|Shell\s+Uploader|tinyfilemanager|alfa_?(?:shell|team)|Sh3ll|h4x0r|\bP\.A\.S\.\s*Fork|marijuana\s*shell)"),
  dict(id="PHP.Backdoor.AdminCreate", name="Code that silently creates an administrator", severity="critical", types=PHP,
       pattern=r"wp_(?:create|insert)_user\s*\([^;]{0,300}\)\s*;[\s\S]{0,300}?->set_role\s*\(\s*['\"]administrator['\"]"),
  dict(id="PHP.Backdoor.AuthBypass", name="Login bypass via wp_set_auth_cookie on request parameter", severity="critical", types=PHP,
       pattern=r"if\s*\(\s*(?:isset\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\][^{]{0,120}\{[^}]{0,300}wp_set_auth_cookie\s*\("),
  dict(id="PHP.Backdoor.HiddenUser", name="Hides a user from the admin users list", severity="high", types=PHP,
       pattern=r"pre_user_query[\s\S]{0,400}?user_login\s*!=\s*['\"]"),
  dict(id="PHP.Mailer.Spam", name="Mass-mailer script", severity="high", types=PHP,
       pattern=r"\bmail\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[[^\]]+\]\s*,\s*\$_(?:POST|GET|REQUEST)"),
  dict(id="JS.Injected.Redirect", name="Injected script redirect / malvertising loader", severity="high", types=WEB,
       pattern=r"(?:String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){30,}|document\.write\s*\(\s*unescape\s*\(\s*['\"]%3c(?:script|iframe)|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)[\s\S]{0,4000}?(?:window\.location|document\.location|\.src\s*=))"),
  dict(id="JS.Cryptominer", name="Browser cryptocurrency miner", severity="high", types=WEB,
       pattern=r"(?:coinhive\.min\.js|CoinHive\.Anonymous|coin-hive\.com|cryptoloot|webminepool|minero\.cc|new\s+CRLT\.Anonymous)"),
  dict(id="JS.Skimmer", name="Payment card skimmer", severity="critical", types=WEB,
       pattern=r"(?:\b(?:cc_?number|cardnumber|card\[number\])\b[\s\S]{0,400}?\b(?:btoa|atob|escape)\s*\([\s\S]{0,400}?(?:new\s+Image\s*\(|navigator\.sendBeacon|XMLHttpRequest))"),
  dict(id="HTML.SEO.Spam", name="Hidden SEO spam links", severity="medium", types=WEB,
       pattern=r"<div[^>]+style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|left\s*:\s*-\d{3,}px|position\s*:\s*absolute;\s*top\s*:\s*-\d{3,}px)[^'\"]*['\"][^>]*>\s*(?:<a\s[^>]*href[^>]*>[^<]*(?:viagra|cialis|casino|payday|replica|porn|escort)[^<]*</a>\s*){2,}"),
]

DB_ALL = ["post", "comment", "option"]
DB_COMMENT = ["comment"]

content_sigs = [
  dict(id="DB.JS.ScriptFromCharCode", name="Obfuscated String.fromCharCode payload", severity="high", types=DB_ALL,
       pattern=r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){25,}"),
  dict(id="DB.JS.DocumentWriteEval", name="document.write(unescape/atob) or eval(atob) injection", severity="critical", types=DB_ALL,
       pattern=r"(?:document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\(|eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\()"),
  dict(id="DB.JS.PackerRedirect", name="Obfuscated packed JS redirect/loader", severity="high", types=DB_ALL,
       pattern=r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)[\s\S]{0,4000}?(?:window\.location|document\.location|\.src\s*=|createElement\s*\(\s*['\"]script['\"])"),
  dict(id="DB.HTML.HiddenIframe", name="Hidden or zero-size external iframe", severity="high", types=DB_ALL,
       pattern=r"<iframe\b(?=[^>]*\bsrc\s*=\s*['\"]?(?:https?:)?//(?!(?:www\.)?googletagmanager\.com/ns\.html\b))(?=[^>]*?(?:\b(?:width|height)\s*=\s*['\"]?[01](?:px)?['\"\s>]|display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}px))[^>]*>"),
  dict(id="DB.HTML.MetaRefreshExternal", name="Injected meta-refresh redirect to external URL", severity="high", types=DB_ALL,
       pattern=r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*url\s*=\s*['\"]?https?://"),
  dict(id="DB.Code.PhpOrEvalStored", name="PHP code or eval(base64_decode) stored in database", severity="critical", types=DB_ALL,
       pattern=r"(?:<\?php\b[\s\S]{0,200}?\b(?:eval|assert|system|exec|passthru|shell_exec|base64_decode|gzinflate)\s*\(|\beval\s*\(\s*(?:base64_decode|gzinflate|\$_(?:GET|POST|REQUEST|COOKIE))\b)"),
  dict(id="DB.JS.SuspiciousScriptSrc", name="Injected script tag from raw IP, data URI, or dropper URL", severity="high", types=DB_ALL,
       pattern=r"<script\b[^>]*\bsrc\s*=\s*['\"]?(?:data\s*:\s*text/javascript|https?://\d{1,3}(?:\.\d{1,3}){3}[:/]|https?://[^'\"\s>]+/(?:get|stat|count|track|loader|go)\.php\?[^'\"\s>]*=)"),
  dict(id="DB.HTML.HiddenSeoSpam", name="Hidden SEO spam link block", severity="medium", types=DB_ALL,
       pattern=r"<(?:div|p|span)\b[^>]+style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|left\s*:\s*-\d{3,}px|top\s*:\s*-\d{3,}px|font-size\s*:\s*0(?:px|em|%)?)[^'\"]*['\"][^>]*>[\s\S]{0,600}?(?:<a\s[^>]*href[^>]*>[^<]*(?:viagra|cialis|casino|poker|slots|payday|replica|porn|escort|buy\s+cheap)[^<]*</a>[\s\S]{0,120}?){2,}"),
  dict(id="DB.JS.Cryptominer", name="Browser cryptocurrency miner", severity="high", types=DB_ALL,
       pattern=r"(?:coinhive\.min\.js|CoinHive\.Anonymous|coin-hive\.com|cryptoloot|webminepool|minero\.cc|new\s+CRLT\.Anonymous)"),
  dict(id="DB.JS.InlineEventXss", name="Injected inline event handler payload", severity="high", types=DB_ALL,
       pattern=r"<(?:img|svg|body|iframe|details)\b[^>]+[\s/\"']on(?:error|load|toggle)\s*=\s*['\"]?\s*(?:eval|atob|fetch|document\.(?:write|cookie|createElement)|window\.location|Function)\b"),
  dict(id="DB.Comment.ScriptOrJsUri", name="Script tag or javascript: URI in comment", severity="high", types=DB_COMMENT,
       pattern=r"(?:<\s*script\b|\bjavascript\s*:)"),
]

seen = set()
for s in sigs + content_sigs:
    assert s["id"] not in seen, s["id"]
    seen.add(s["id"])

here = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(here, "..", "includes", "Scanner", "signatures.json")
with open(path, "w") as f:
    json.dump({"schema": 1, "version": "2026.11.23", "signatures": sigs, "content_signatures": content_sigs}, f, indent=1)
    f.write("\n")
print(f"wrote {len(sigs)} file signatures and {len(content_sigs)} content signatures to {os.path.normpath(path)}")
