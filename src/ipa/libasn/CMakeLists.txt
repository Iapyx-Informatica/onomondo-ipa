# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# libasn: the asn1c-generated ASN.1 codec.
#
# The C sources are generated (not committed) into ${LIBASN_GEN_DIR} in the
# build tree.  Generation is driven from the top-level CMakeLists.txt -- it has
# to happen before the asn1c-API-drift detection there, which inspects the
# generated headers -- so by the time this file is processed the sources
# already exist on disk.  Here we only glob them and define the library target.

file(GLOB LIBASN_SOURCES CONFIGURE_DEPENDS ${LIBASN_GEN_DIR}/*.c)
if(NOT LIBASN_SOURCES)
  message(FATAL_ERROR "libasn: no generated sources found in ${LIBASN_GEN_DIR}")
endif()

add_library(libasn STATIC ${LIBASN_SOURCES})

# libasn is generated code; its remaining warnings (structs declared inside
# parameter lists, unused variables) are generator artifacts we cannot fix
# without editing generated files.  Build it without warnings, and expose its
# headers as SYSTEM includes so they stay quiet in the hand-written targets
# (libipa, ipa, the tests) that include them too.  Warnings in our own code
# remain visible: only libasn is exempted.
target_compile_options(libasn PRIVATE -w)
target_include_directories(libasn PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_include_directories(libasn SYSTEM PUBLIC ${LIBASN_GEN_DIR})

if (M32)
  set_target_properties(libasn PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()
