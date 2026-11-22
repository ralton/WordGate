#!/usr/bin/env bash
# Build an installable plugin zip (Plugins → Add New → Upload Plugin).
#
#   tools/build-zip.sh            -> dist/wordgate-<version>.zip
#
# Packages committed files only (git archive), so uncommitted work never ships,
# and removes everything listed in .distignore. The archive's top-level folder
# is "wordgate/" so the plugin installs as wordgate/wordgate.php.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^ \* Version:[[:space:]]*//p' wordgate.php | head -1)"
[ -n "$version" ] || { echo "Could not read Version from wordgate.php" >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

git archive --format=tar --prefix=wordgate/ HEAD | tar -x -C "$stage"

while IFS= read -r line; do
	line="${line%%#*}"; line="${line// /}"
	[ -z "$line" ] && continue
	rm -rf "$stage/wordgate/${line#/}"
done < .distignore

# Sanity checks: the things WordPress needs must be present.
for f in wordgate.php uninstall.php readme.txt LICENSE waf/bootstrap.php waf/rules/default.json includes/Scanner/signatures.json assets/vendor/qrcode.js; do
	[ -e "$stage/wordgate/$f" ] || { echo "Missing $f in package" >&2; exit 1; }
done

mkdir -p dist
out="dist/wordgate-${version}.zip"
rm -f "$out"
python3 -I - "$stage" "$root/$out" <<'PY'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for dirpath, dirs, files in os.walk(os.path.join(stage, "wordgate")):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            z.write(full, os.path.relpath(full, stage))
PY
echo "Built $out ($(du -h "$out" | cut -f1), $(python3 -I -c 'import zipfile,sys;print(len(zipfile.ZipFile(sys.argv[1]).namelist()))' "$out") files)"
