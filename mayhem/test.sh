#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests over tbox's own demo binary (src/demo, the program upstream's CI
# runs as its test: `xmake run demo`). build.sh built it with normal flags in build/test. Each case runs
# one demo subcommand on a fixed input and diffs its output (stdout+stderr, or the file it writes)
# against mayhem/tests/expected/<case>; the inputs live in mayhem/tests/input. Only deterministic demos
# are used (no timings, no network, no clock-dependent cookies beyond 2038).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

DEMO=build/test/linux/x86_64/release/demo
T=mayhem/tests
if [ ! -x "$DEMO" ]; then
  echo "FAIL: $DEMO missing — mayhem/build.sh did not build the demo" >&2
  emit_ctrf "tbox-demo-kat" 0 1
  exit 1
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tbox-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
passed=0 failed=0

# check <case> <file-with-actual-output>
check() {
  if cmp -s "$T/expected/$1" "$2"; then
    passed=$((passed + 1)); echo "PASS $1"
  else
    failed=$((failed + 1)); echo "FAIL $1"; diff "$T/expected/$1" "$2" | head -20
  fi
}
# out <case> <demo args...>: compare the demo's console output
out() { local c="$1"; shift; "$DEMO" "$@" > "$WORK/$c" 2>&1; check "$c" "$WORK/$c"; }

out base64_encode   utils_base64 hello
out base32_decode   utils_base32 NBSWY3DP
out url_decode      utils_url 'a%20b%2Fc+d'
out ipv4            network_ipv4 192.168.1.254
out ipv6            network_ipv6 fe80::7a31:c1ff:fecf:e8ae%7
out hwaddr          network_hwaddr aa:bb:cc:dd:ee:ff
# network_url resolves relative file paths against the cwd: run it from / so the output is fixed
DEMO_ABS="$PWD/$DEMO"
(cd / && "$DEMO_ABS" network_url) > "$WORK/url_parse" 2>&1
check url_parse "$WORK/url_parse"
out cookies         network_cookies
out md5             hash_md5 abc
out sha             hash_sha abc
out crc32           hash_crc32 abc
out adler32         hash_adler32 abc
out fnv32           hash_fnv32 abc
out string          string_string
out static_string   string_static_string
out object_json     object_dump "$T/input/object.json"
out object_xplist   object_dump "$T/input/object.xplist"
out object_bin      object_dump "$T/input/object.bin"

# xml_document: parse + re-serialise to a file
"$DEMO" xml_document "$T/input/doc.xml" "$WORK/doc.out.xml" > /dev/null 2>&1
check xml_document "$WORK/doc.out.xml"

# charset: utf8 -> utf16 (big endian) -> gb2312
"$DEMO" other_charset "$T/input/text.utf8" "$WORK/text.utf16" utf8 utf16 > /dev/null 2>&1
check charset_utf16 "$WORK/text.utf16"
"$DEMO" other_charset "$WORK/text.utf16" "$WORK/text.gb2312" utf16 gb2312 > /dev/null 2>&1
check charset_gb2312 "$WORK/text.gb2312"

emit_ctrf "tbox-demo-kat" "$passed" "$failed"
