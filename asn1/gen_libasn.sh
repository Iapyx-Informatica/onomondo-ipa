#!/usr/bin/env bash
# Generate the libasn ASN.1 codec (C sources) from asn1/*.asn using asn1c.
#
# Usage:
#   gen_libasn.sh <asn1c> <asn_src_dir> <out_dir>
#
#   <asn1c>        path to the asn1c executable
#   <asn_src_dir>  directory holding the *.asn schema + patch files (this dir)
#   <out_dir>      directory to (re)generate the C sources into
#
# This script is invoked by src/ipa/libasn/CMakeLists.txt; CMake owns *when* it
# runs (only when the schema or this script changes, or the tree is missing).
# It intentionally does NOT emit a CMakeLists.txt -- the source list is globbed
# from <out_dir> by CMake.
#
# asn1c has no incremental mode: it always regenerates the *entire* codec from
# all schemas in one pass.  If we simply overwrote <out_dir> every time, every
# generated .c/.h would get a fresh timestamp and make/ninja would recompile the
# whole codec -- and everything that includes its headers -- on any schema edit,
# even a whitespace-only one.  To avoid that, we generate into a staging dir and
# then copy into <out_dir> only the files whose *content* actually changed, so
# unchanged files keep their mtimes and the build stays incremental.
#
# The output is a pure function of the .asn inputs plus the two patches and the
# post-processing renames below, so regenerating is idempotent.

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <asn1c> <asn_src_dir> <out_dir>" >&2
  exit 2
fi

ASN1C="$1"
# Absolutise so the paths survive the `cd` into the staging dir below.
ASN_SRC_DIR="$(cd "$2" && pwd)"
mkdir -p "$3"
OUT_DIR="$(cd "$3" && pwd)"
# Staging is a sibling of OUT_DIR (not underneath it, so CMake's *.c glob on
# OUT_DIR never sees it).
STAGING="${OUT_DIR}.staging"

# Schema files, in the historical (known-good) order.  asn1c compiles them all
# in one invocation; the modules cross-reference each other.
ASN_FILES=(
  "${ASN_SRC_DIR}/PKIX1Explicit88.asn"
  "${ASN_SRC_DIR}/PKIX1Implicit88.asn"
  "${ASN_SRC_DIR}/PEDefinitions.asn"
  "${ASN_SRC_DIR}/RSPDefinitions.asn"
  "${ASN_SRC_DIR}/SGP32Definitions.asn"
)

PATCH_ALLOC="${ASN_SRC_DIR}/0001-asn_internal-use-custom-memory-allocator-functions.patch"

echo "[gen_libasn] asn1c: ${ASN1C}"
echo "[gen_libasn] out:   ${OUT_DIR}"

# --- Generate the full codec into a clean staging directory ---------------
rm -rf "${STAGING}"
mkdir -p "${STAGING}"

# Compile ASN.1 -> C.  -no-gen-example is only on asn1c master (post-0.9.28);
# probe and pass it if available, otherwise delete the example files afterwards.
# -fcompound-names keeps type names unique across the merged modules.
ASN1C_FLAGS=(-fcompound-names)
if "${ASN1C}" -h 2>&1 | grep -q -- "-no-gen-example"; then
  ASN1C_FLAGS+=(-no-gen-example)
fi

( cd "${STAGING}" && "${ASN1C}" "${ASN1C_FLAGS[@]}" "${ASN_FILES[@]}" )

# Drop generator by-products we do not build: the automake fragments and the
# standalone converter/sample programs (they carry their own main()).  asn1c
# master names these *-example.*; packaged 0.9.28 names them *-sample.* and also
# emits Makefile.am.sample -- cover both.
rm -f "${STAGING}"/Makefile.am.libasncodec "${STAGING}"/Makefile.am.sample \
      "${STAGING}"/converter-example.c "${STAGING}"/converter-example.mk \
      "${STAGING}"/converter-sample.c  "${STAGING}"/converter-sample.mk \
      "${STAGING}"/*-example.c "${STAGING}"/*-example.mk \
      "${STAGING}"/*-sample.c  "${STAGING}"/*-sample.mk

# --- Patch: route asn1c allocations through libipa's IPA_* allocators -------
# Redirects CALLOC/MALLOC/REALLOC/FREEMEM in asn_internal.h to <onomondo/ipa/
# mem.h> so the generated codec honours the project allocator (and the
# MEM_EMIT_DEBUG heap instrumentation).  The patch carries a git-style path
# (a/src/ipa/libasn/asn_internal.h), so strip four leading components with -p4
# and apply inside STAGING.
patch -p4 -d "${STAGING}" < "${PATCH_ALLOC}"

# Clean up patch backups so they aren't mistaken for sources.
find "${STAGING}" -maxdepth 1 \( -name '*.orig' -o -name '*.rej' \) -delete

# --- asn1c-version normalisations (orthogonal to the SGP.32 spec version) ---
# asn1c emits Time.{c,h} for the PKIX Time type.  On case-insensitive
# filesystems this clashes with the system <time.h> that GeneralizedTime.c
# includes.  Rename to PKIX_Time.{c,h} and fix references so both coexist.
if [ -f "${STAGING}/Time.h" ]; then
  mv "${STAGING}/Time.h" "${STAGING}/PKIX_Time.h"
  mv "${STAGING}/Time.c" "${STAGING}/PKIX_Time.c"
  grep -l '"Time\.h"' "${STAGING}"/*.c "${STAGING}"/*.h 2>/dev/null \
    | xargs -r perl -pi -e 's|"Time\.h"|"PKIX_Time.h"|g'
  echo "[gen_libasn] renamed Time.{c,h} -> PKIX_Time.{c,h}"
fi

# asn1c master escapes the C++ keyword `delete` as `Delete` in the Psmo union,
# while 0.9.28 leaves it lowercase.  Normalise to lowercase so libipa can use
# `psmo->choice.delete` regardless of which asn1c produced the tree.
if [ -f "${STAGING}/Psmo.h" ] && grep -qE '\} Delete;' "${STAGING}/Psmo.h" 2>/dev/null; then
  perl -pi -e 's/\.Delete\b/.delete/g; s/\} Delete;/} delete;/g; s/choice\.Delete\b/choice.delete/g' \
    "${STAGING}/Psmo.h" "${STAGING}/Psmo.c"
  echo "[gen_libasn] normalised Psmo.Delete -> Psmo.delete"
fi

# --- Sync staging -> OUT_DIR, touching only files that actually changed -----
mkdir -p "${OUT_DIR}"

# 1. Remove sources that no longer exist (e.g. a type deleted from a schema).
for existing in "${OUT_DIR}"/*.c "${OUT_DIR}"/*.h; do
  [ -e "${existing}" ] || continue          # no matches -> literal glob, skip
  base="$(basename "${existing}")"
  if [ ! -e "${STAGING}/${base}" ]; then
    rm -f "${existing}"
    echo "[gen_libasn] removed stale ${base}"
  fi
done

# 2. Copy only new / content-changed files; unchanged files keep their mtime.
changed=0
for f in "${STAGING}"/*.c "${STAGING}"/*.h; do
  base="$(basename "${f}")"
  if ! cmp -s "${f}" "${OUT_DIR}/${base}"; then
    cp "${f}" "${OUT_DIR}/${base}"
    changed=$((changed + 1))
  fi
done

rm -rf "${STAGING}"

echo "[gen_libasn] done: $(ls -1 "${OUT_DIR}"/*.c 2>/dev/null | wc -l) .c sources, ${changed} file(s) updated"
