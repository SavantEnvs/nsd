#!/usr/bin/env bash
#
# mayhem/test.sh — run NSD's own tests (built by mayhem/build.sh into mayhem/build-test):
#   1. cutest: the unit-test suite in tpkg/cutest (CuTest; "OK (N tests)" on success).
#   2. cutest -q: the known-answer query tests of tpkg/cutest_qroot.tdir (root2, unsigned,
#      root): every query's answer is compared with the recorded one ("check OK").
#   3. nsd-checkzone -p on mayhem/tests/example.com.zone, diffed against the golden print;
#      and a zone with a bad A record must be rejected with its error.
#   4. nsd-checkconf -o / -z queries on mayhem/tests/nsd.conf, compared with known values.
# Emits a CTRF report; exit non-zero iff a test failed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

B="$SRC/mayhem/build-test"
for exe in cutest popen3_echo nsd-checkzone nsd-checkconf; do
  if [ ! -x "$B/$exe" ]; then
    echo "test.sh: $B/$exe missing — run mayhem/build.sh first" >&2
    emit_ctrf cutest 0 1
    exit 1
  fi
done

passed=0; failed=0; skipped=0
ok()   { echo "PASS: $1"; passed=$((passed + 1)); }
bad()  { echo "FAIL: $1"; failed=$((failed + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/nsd-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# 1. unit tests (run in the build dir: the popen3 tests exec ./popen3_echo)
out="$(cd "$B" && timeout 900 ./cutest 2>&1)"; rc=$?
echo "$out" | tail -5
if [ $rc -eq 0 ] && n="$(echo "$out" | sed -n -E 's/^OK \(([0-9]+) tests?\)$/\1/p')" && [ -n "$n" ] && [ "$n" -gt 0 ]; then
  passed=$((passed + n))
  s="$(echo "$out" | sed -n -E 's/^SKIP \(([0-9]+) tests?\)$/\1/p')"; skipped=$((skipped + ${s:-0}))
  echo "PASS: cutest ($n unit tests)"
else
  f="$(echo "$out" | sed -n -E 's/.*Passed: ([0-9]+) Failed: ([0-9]+).*/\1 \2/p')"
  if [ -n "$f" ]; then
    passed=$((passed + ${f% *})); failed=$((failed + ${f#* }))
  else
    failed=$((failed + 1))
  fi
  echo "FAIL: cutest (rc=$rc)"
fi

# 2. query known-answer tests
cp -r tpkg/cutest_qroot.tdir "$work/qroot"
for q in root2 unsigned root; do
  out="$(cd "$work/qroot" && "$B/cutest" -c "$q.conf" -q "$q.qfile" 2>&1)"; rc=$?
  nq="$(echo "$out" | sed -n -E 's/^qfile has ([0-9]+) queries$/\1/p')"
  if [ $rc -eq 0 ] && echo "$out" | grep -qx "check OK" && [ "${nq:-0}" -gt 0 ]; then
    ok "qtest $q ($nq queries)"
  else
    echo "$out" | tail -20; bad "qtest $q"
  fi
done

# 3. zone check + print
T="$SRC/mayhem/tests"
out="$(cd "$T" && "$B/nsd-checkzone" -p example.com example.com.zone 2>&1)"; rc=$?
if [ $rc -eq 0 ] && diff -u "$T/example.com.zone.expected" <(echo "$out"); then
  ok "nsd-checkzone -p golden print"
else
  bad "nsd-checkzone -p golden print (rc=$rc)"
fi
out="$(cd "$T" && "$B/nsd-checkzone" example.com bad.zone 2>&1)"; rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -q "bad.zone:4: Invalid address in A" \
   && echo "$out" | grep -q "zone example.com file bad.zone has 1 errors"; then
  ok "nsd-checkzone rejects bad A record"
else
  echo "$out"; bad "nsd-checkzone rejects bad A record (rc=$rc)"
fi

# 4. config queries
check_conf() {  # <expected> <args...>
  local want="$1"; shift
  local got; got="$(cd "$T" && "$B/nsd-checkconf" "$@" nsd.conf 2>&1)"
  if [ "$got" = "$want" ]; then ok "nsd-checkconf $*"; else echo "got: $got"; bad "nsd-checkconf $* (want '$want')"; fi
}
check_conf "/var/nsd/zones" -o zonesdir
check_conf "1232" -o ipv4-edns-size
check_conf "192.0.2.2 tsig.example." -z example.com -o request-xfr
check_conf "example.com.zone" -z example.com -o zonefile

emit_ctrf nsd-cutest "$passed" "$failed" "$skipped"
