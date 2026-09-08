#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

tmp=${TMPDIR:-/tmp}/fatpix-acceptance.$$
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp"

python3 -m py_compile clarity.py fatpix

check_real() {
    specimen=$1
    expected=$2
    [ -f "$specimen" ] || { echo "missing acceptance specimen: $specimen" >&2; exit 1; }
    ./clarity.py --analyze --json "$specimen" >"$tmp/result.json"
    python3 - "$tmp/result.json" "$expected" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
views = result.get("views", [])
if not any(v.get("ksy_id") == expected and v.get("strong_identity") for v in views):
    raise SystemExit(f"{expected}: no evidence-backed real-corpus structural view")
PY
}

# Format acceptance is deliberately end-to-end: ordinary specimens, anonymous
# input, automatic nomination, and definitions from this repository's real
# Kaitai corpus.  Never replace these with generated friendly KSY files.
check_real test/sample.png png
check_real test/x86_64.elf elf
check_real test/george.zip zip
check_real test/george.gz gzip
check_real test/george.tar.gz gzip
check_real test/sample.iso iso9660
check_real test/sample.sqlite sqlite3

# Run PE acceptance when an ordinary PE specimen is present in the corpus.
pe=$(find test -maxdepth 1 -type f \( -iname '*.exe' -o -iname '*.dll' \) -print -quit)
if [ -n "$pe" ]; then
    check_real "$pe" microsoft_pe
fi

dd if=/dev/zero of="$tmp/blank" bs=65536 count=1 2>/dev/null
python3 - "$tmp/random" <<'PY'
import os, sys
open(sys.argv[1], "wb").write(os.urandom(65536))
PY
for negative in "$tmp/blank" "$tmp/random"; do
    ./clarity.py --analyze --json "$negative" >"$tmp/negative.json"
    python3 - "$tmp/negative.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
if any(v.get("strong_identity") for v in result.get("views", [])):
    raise SystemExit("negative specimen received a strong structural identity")
PY
done

echo "real-corpus Clarity acceptance tests passed"
