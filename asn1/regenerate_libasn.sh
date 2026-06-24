#!/bin/bash

set -e

cd ../src/ipa/libasn/

# Remove an old implementation
rm -f *.c
rm -f *.h
rm -f Makefile.am.libasncodec

# Compile ASN.1 specification to actual C implementation.
# -no-gen-example is only supported on asn1c master (post-0.9.28); detect and
# pass it if available.  On packaged 0.9.28 we drop the flag and delete the
# example files afterwards.
# We rely on the per-type range constraint in PKIX1Explicit88.asn's
# CertificateSerialNumber to get INTEGER_t for that one field, leaving all
# other ASN.1 INTEGERs as plain long (libipa expects long for enum values).
ASN1C_FLAGS="-fcompound-names"
if asn1c -h 2>&1 | grep -q -- "-no-gen-example"; then
  ASN1C_FLAGS="${ASN1C_FLAGS} -no-gen-example"
fi

asn1c ${ASN1C_FLAGS} \
      ../../../asn1/PKIX1Explicit88.asn \
      ../../../asn1/PKIX1Implicit88.asn \
      ../../../asn1/PEDefinitions.asn \
      ../../../asn1/RSPDefinitions.asn \
      ../../../asn1/SGP32Definitions.asn

# Remove file(s) we do not need (asn1c emits Makefile.am.libasncodec and,
# on 0.9.28 without -no-gen-example, a handful of example / converter files).
rm -f Makefile.am.libasncodec
rm -f converter-example.c converter-example.mk
rm -f *-example.c *-example.mk

# Generate CMakeLists.txt
echo "#CAUTION: autgenerated file, do not change, see "`basename $0` > CMakeLists.txt
echo 'add_library(libasn STATIC' >> CMakeLists.txt
ls -1 *.h *.c >> CMakeLists.txt
echo ')' >> CMakeLists.txt
echo 'target_include_directories(libasn PUBLIC ${CMAKE_SOURCE_DIR}/include PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})' >> CMakeLists.txt
echo 'target_compile_options(libasn PRIVATE -Wall)' >> CMakeLists.txt
echo 'if (M32)' >> CMakeLists.txt
echo '  set_target_properties(libasn PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")' >> CMakeLists.txt
echo 'endif()' >> CMakeLists.txt


# Re-apply patches to generated sourcecode.
# NOTE: the PKIX1Explicit88 patch was needed when CertificateSerialNumber
# carried a huge INTEGER range constraint to force INTEGER_t.  We now drive
# that with -fwide-types above, so the constraint (and the patch) are both
# no longer required.  Kept as optional for parity with upstream.
cd ../../../
if patch -p1 --dry-run < ./asn1/0001-PKIX1Explicit88-remove-broken-constraint-check-in-Ce.patch >/dev/null 2>&1; then
  patch -p1 < ./asn1/0001-PKIX1Explicit88-remove-broken-constraint-check-in-Ce.patch
else
  echo "[regen] CertificateSerialNumber patch no longer applies (schema was simplified); skipping"
fi
# Clean up .orig / .rej so CMake doesn't try to compile them
find src/ipa/libasn -maxdepth 1 -name '*.orig' -o -name '*.rej' | xargs rm -f
patch -p1 < ./asn1/0001-asn_internal-use-custom-memory-allocator-functions.patch

# asn1c generates a file called Time.h for the PKIX Time type.  On
# case-insensitive filesystems (Windows/macOS, and when a Linux docker
# container mounts a Windows volume) this collides with the system
# <time.h> that GeneralizedTime.c needs.  Rename to PKIX_Time.{c,h} and
# fix up all references so both coexist.
cd src/ipa/libasn
if [ -f Time.h ]; then
  mv Time.h PKIX_Time.h
  mv Time.c PKIX_Time.c
  # Update #include "Time.h" -> "PKIX_Time.h" across the whole codec.
  # Use grep -l to find affected files, then sed each.
  grep -l '"Time\.h"' ./*.c ./*.h 2>/dev/null | xargs perl -pi -e 's|"Time\.h"|"PKIX_Time.h"|g'
  echo "[regen] renamed PKIX Time.{c,h} -> PKIX_Time.{c,h} (avoid clash with system <time.h>)"
fi

# asn1c master escapes the C++ keyword `delete` as a capitalised member
# name `Delete` in the Psmo union (e.g. `} Delete;`), while asn1c 0.9.28
# leaves it lowercase.  Normalise to lowercase so libipa caller code can
# use `psmo->choice.delete` regardless of which asn1c generated the headers.
# Detection: look for the capitalised member declaration specifically — the
# struct type name is `Psmo__delete` (lowercase) in BOTH versions, so checking
# for `Psmo__Delete` misses the master case.
if [ -f Psmo.h ] && grep -qE '\} Delete;' Psmo.h 2>/dev/null; then
  perl -pi -e 's/\.Delete\b/.delete/g; s/\} Delete;/} delete;/g; s/choice\.Delete\b/choice.delete/g' \
    Psmo.h Psmo.c
  echo "[regen] normalised Psmo.Delete -> Psmo.delete (asn1c-version compat)"
fi

cd ../../../

# Regenerate CMakeLists.txt so it picks up the renamed files.
cd src/ipa/libasn
{
  echo "#CAUTION: autgenerated file, do not change, see regenerate_libasn.sh"
  echo 'add_library(libasn STATIC'
  ls -1 ./*.h ./*.c
  echo ')'
  echo 'target_include_directories(libasn PUBLIC ${CMAKE_SOURCE_DIR}/include PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})'
  echo 'target_compile_options(libasn PRIVATE -Wall)'
  echo 'if (M32)'
  echo '  set_target_properties(libasn PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")'
  echo 'endif()'
} > CMakeLists.txt
cd ../../../
