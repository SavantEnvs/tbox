#!/usr/bin/env bash
#
# mayhem/build.sh — build tbox's fuzz harnesses and the demo binary test.sh drives.
#
# tbox ships a configure script (xmake.sh-based) that writes a plain Makefile into the source root
# (gitignored upstream) and puts objects + the generated tbox.config.h under --builddir. Two builds:
#   build/fuzz  libtbox.a with $SANITIZER_FLAGS $DEBUG_FLAGS  -> linked into every harness
#   build/test  libtbox.a + the upstream demo binary with normal flags -> mayhem/test.sh
# Both are release mode (quiet tracing) with --small=no and the parser modules (xml, object, charset,
# hash) enabled; zip/regex/database stay off (they only wrap zlib/pcre/sqlite).
# Why release, not debug: debug mode defines __tb_debug__, and then every tb_assert_and_check_* input
# check becomes an aborting tb_assert (tb_assert_impl -> tb_abort, src/tbox/prefix/assert.h), so any
# malformed input would crash (e.g. object/impl/reader/json.c tb_assert_and_check_break_state on an
# unparseable array item). Release keeps those as graceful tb_check_* rejects, which is tbox's
# production behaviour. The plain tb_asserts that release compiles out are followed by the same check
# in code (e.g. object/impl/reader/bplist.c `tb_assert(item < object_count && object_hash[item])` and
# the `if` on the same condition right after), so no check on untrusted input is hidden.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export CC CXX

cd "${SRC:-/mayhem}"
MODULES=(--small=no --xml=yes --object=yes --charset=yes --hash=yes)
LIBDIR=linux/x86_64/release

# 1) test build: normal flags (+ optional coverage), demo enabled
[ "$(cat build/test/.cflags 2>/dev/null)" = "$COVERAGE_FLAGS" ] || rm -rf build/test
mkdir -p build/test && printf '%s' "$COVERAGE_FLAGS" > build/test/.cflags
env -u CFLAGS -u CXXFLAGS -u LDFLAGS CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    ./configure --toolchain=clang --mode=release --demo=yes "${MODULES[@]}" --builddir=build/test
make -j"$MAYHEM_JOBS"
test -x "build/test/$LIBDIR/demo"

# 2) sanitized + coverage-instrumented library for the harnesses. -fsanitize=fuzzer-no-link is added
#    unconditionally (also when SANITIZER_FLAGS is empty) so the library code carries SanCov edges.
#    Three UBSan checks that fire on benign, pervasive tbox idioms are relaxed (ASan and the rest of
#    UBSan stay on and halting; an empty SANITIZER_FLAGS drops the relaxation with the sanitizers):
#      alignment         containers store elements at packed, unaligned offsets by design
#                        (container/element/ptr.c `*((tb_cpointer_t*)buff) = data`), hit inside tb_init()
#      shift-base        byte-assembly helpers shift into the sign bit of int (utils/bits.h
#                        tb_bits_get_u32_be, utils/base64.c decode), on nearly every binary input
#      pointer-overflow  `NULL + 0` on empty static streams (stream/impl/filter/cache.c spak)
#    shift-exponent (e.g. network/ipv4.c shifting by >= 32) stays enabled.
RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) RELAX="-fno-sanitize=alignment,shift-base,pointer-overflow" ;; esac
FUZZ_CFLAGS="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
# the generated Makefile does not track flags: start build/fuzz over when they changed
[ "$(cat build/fuzz/.cflags 2>/dev/null)" = "$FUZZ_CFLAGS" ] || rm -rf build/fuzz
mkdir -p build/fuzz && printf '%s' "$FUZZ_CFLAGS" > build/fuzz/.cflags
env -u CXXFLAGS -u LDFLAGS CFLAGS="$FUZZ_CFLAGS" \
    ./configure --toolchain=clang --mode=release --demo=no "${MODULES[@]}" --builddir=build/fuzz
make -j"$MAYHEM_JOBS"
LIB="build/fuzz/$LIBDIR/libtbox.a"
test -f "$LIB"

# 3) harnesses: libFuzzer binary + run-once standalone reproducer, LSan off at build time
OUT=build/fuzzers
mkdir -p "$OUT"
CFLAGS_H=($SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -std=gnu99 -Isrc -I"build/fuzz/$LIBDIR")
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC "${CFLAGS_H[@]}" -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
LIBS=("$LIB" -lpthread -ldl -lm)
for src in mayhem/harnesses/fuzz_*.c; do
    name=$(basename "$src" .c)
    $CC "${CFLAGS_H[@]}" -c "$src" -o "$OUT/$name.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" "${LIBS[@]}" -o "$OUT/$name"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" "$OUT/lsan_off.o" "${LIBS[@]}" -o "$OUT/$name-standalone"
done
ls -l "$OUT"
