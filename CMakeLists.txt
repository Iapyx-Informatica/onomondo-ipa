# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.13...3.19 FATAL_ERROR)
project(ipa VERSION 0.0.1 LANGUAGES C)

option(ENABLE_SANITIZE "Compile with address sanitizer enabled" OFF)
option(SHOW_ASN_OUTPUT "Show ASN.1 decoded output in the log" OFF)
option(ASN_EMIT_DEBUG "Enable built-in debug output of asn1c" OFF)
option(MEM_EMIT_DEBUG "Enable debug output for heap memory usage" OFF)
option(M32 "Compile for 32 bit mode" OFF)

if (ENABLE_SANITIZE)
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif()

if(SHOW_ASN_OUTPUT)
  add_definitions(-DSHOW_ASN_OUTPUT)
endif()

if(ASN_EMIT_DEBUG)
  add_definitions(-DASN_EMIT_DEBUG)
endif()

if(MEM_EMIT_DEBUG)
  add_definitions(-DMEM_EMIT_DEBUG)
endif()

# asn1c's asn_system.h defines _BSD_SOURCE, which glibc deprecated in favour of
# _DEFAULT_SOURCE: without the latter, _BSD_SOURCE no longer enables the features
# asn1c expects and every translation unit that includes asn_system.h warns.
# asn_system.h is pulled in well beyond libasn (libipa, ipa, the tests), so this
# has to be defined for the whole project rather than per-target.
add_compile_definitions(_DEFAULT_SOURCE)

# asn1c API drift detection.  asn1c has diverged between tagged 0.9.28 and
# master in a few subtle ways that we can't fully hide at the .asn level.
# We detect each at configure time and set compile defines so libipa picks
# the right call form for whichever asn1c produced the generated tree.
set(_oid_header "${CMAKE_CURRENT_SOURCE_DIR}/src/ipa/libasn/OBJECT_IDENTIFIER.h")
if(EXISTS "${_oid_header}")
  file(READ "${_oid_header}" _oid_h_contents)
  if("${_oid_h_contents}" MATCHES "_arc_type_size")
    message(STATUS "asn1c 0.9.28 OBJECT_IDENTIFIER_get_arcs signature detected (4-arg)")
    add_compile_definitions(ASN1C_OID_GET_ARCS_4ARG=1)
  else()
    message(STATUS "asn1c master OBJECT_IDENTIFIER_get_arcs signature detected (3-arg)")
  endif()
endif()

# asn1c 0.9.28 keeps method pointers (print_struct, free_struct, ...) as
# direct members of asn_TYPE_descriptor_s.  asn1c master moved them into
# an `op` sub-struct so calls become `td->op->print_struct(...)`.
set(_ct_header "${CMAKE_CURRENT_SOURCE_DIR}/src/ipa/libasn/constr_TYPE.h")
if(EXISTS "${_ct_header}")
  file(READ "${_ct_header}" _ct_h_contents)
  if("${_ct_h_contents}" MATCHES "asn_TYPE_operation_t|struct asn_TYPE_operation")
    message(STATUS "asn1c master TYPE descriptor layout detected (td->op->print_struct)")
    add_compile_definitions(ASN1C_TYPE_HAS_OP=1)
  else()
    message(STATUS "asn1c 0.9.28 TYPE descriptor layout detected (td->print_struct)")
  endif()
endif()

add_subdirectory(src)

include(CTest)
add_subdirectory(tests)
