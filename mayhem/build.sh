#!/usr/bin/env bash
#
# mayhem/build.sh — build NSD's fuzz harnesses and its unit-test suite.
#
# NSD is autoconf + make, with the simdzone zone parser as a git submodule that
# nsd's configure configures and builds (simdzone/libzone.a). Two out-of-tree
# builds of the same source, both under mayhem/ (gitignored by mayhem/.gitignore):
#   mayhem/build-fuzz  the project with $SANITIZER_FLAGS $DEBUG_FLAGS + SanCov
#                      (-fsanitize=fuzzer-no-link); its objects (minus the ones
#                      holding a main()) are linked into each harness.
#   mayhem/build-test  the project with its normal flags: cutest (the unit tests
#                      in tpkg/cutest), nsd-checkzone and nsd-checkconf for test.sh.
# Outputs: mayhem/out/<harness> (libFuzzer) and mayhem/out/<harness>-standalone.
#
# Re-runnable and offline: configure runs only when a build dir has no Makefile,
# and nothing is fetched (openssl comes from the base image; libevent is replaced
# by nsd's bundled mini_event; dnstap is disabled — it needs protobuf-c).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
if [ ! -f simdzone/configure.ac ]; then
  echo "simdzone submodule is missing: check out with submodules (git submodule update --init)" >&2
  exit 1
fi

# configure (and simdzone/configure) are generated, and gitignored upstream.
if [ ! -x configure ] || [ ! -x simdzone/configure ]; then
  autoreconf -fi
  (cd simdzone && autoreconf -fi)
fi

CONF_ARGS=(--disable-flto --disable-dnstap --with-libevent=no)

# ---------------------------------------------------------------- fuzz build
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
mkdir -p mayhem/build-fuzz mayhem/out
(
  cd mayhem/build-fuzz
  if [ ! -f Makefile ]; then
    ../../configure CC="$CC" CFLAGS="$FUZZ_CFLAGS" "${CONF_ARGS[@]}"
  fi
  # nsd-checkzone pulls in every object the harnesses need.
  make -j"$MAYHEM_JOBS" nsd-checkzone
  # All project objects except the ones that define main().
  objs=$(ls ./*.o | grep -v -E '/(nsd|nsd-checkzone|nsd-checkconf|nsd-control|nsd-mem|xfr-inspect|cutest.*|qtest|popen3_echo)\.o$')
  rm -f libnsd-fuzz.a
  ar rcs libnsd-fuzz.a $objs
)

BF=mayhem/build-fuzz
NSD_LIBS="$(sed -n -E 's/^(SSL_)?LIBS[[:space:]]*=[[:space:]]*//p' "$BF/Makefile" | tr '\n' ' ')"
INCS=(-I"$BF" -I"$SRC" -I"$BF/simdzone/include" -I"$SRC/simdzone/include" -I"$SRC/mayhem/harnesses")

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$BF/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BF/standalone_main.o"

build_harness() {  # <output name> <source> [extra cflags...]
  local name="$1" src="$2"; shift 2
  $CC $FUZZ_CFLAGS "${INCS[@]}" "$@" -c "$src" -o "$BF/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BF/$name.o" "$BF/lsan_off.o" \
    "$BF/libnsd-fuzz.a" "$BF/simdzone/libzone.a" $NSD_LIBS -o "mayhem/out/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$BF/$name.o" "$BF/standalone_main.o" \
    "$BF/lsan_off.o" "$BF/libnsd-fuzz.a" "$BF/simdzone/libzone.a" $NSD_LIBS \
    -o "mayhem/out/$name-standalone"
}

build_harness fuzz_query       mayhem/harnesses/fuzz_query.c
build_harness fuzz_zonefile    mayhem/harnesses/fuzz_zonefile.c
build_harness fuzz_ixfr_create mayhem/harnesses/fuzz_zonefile.c -DFUZZ_IXFR_CREATE
build_harness fuzz_ixfr_apply  mayhem/harnesses/fuzz_ixfr_apply.c

build_harness fuzz_nsdconf     mayhem/harnesses/fuzz_nsdconf.c

# ---------------------------------------------------------------- test build
mkdir -p mayhem/build-test
(
  cd mayhem/build-test
  if [ ! -f Makefile ]; then
    ../../configure CC="$CC" CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" "${CONF_ARGS[@]}"
  fi
  make -j"$MAYHEM_JOBS" cutest nsd-checkzone nsd-checkconf
)
echo "build.sh: done"
