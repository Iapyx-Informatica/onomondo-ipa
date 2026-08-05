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

# ---------------------------------------------------------------------------
# libasn source generation (asn1c).
#
# The ASN.1 codec under src/ipa/libasn is generated from asn1/*.asn and is NOT
# committed.  CMake owns generation the way it owns compilation: asn1c runs
# only when the generated tree is missing, or when a schema / the generator
# script has changed.  This has to run *before* the asn1c-API-drift detection
# below (which inspects the generated headers), so it lives here at the top
# level; src/ipa/libasn/CMakeLists.txt merely globs the result and builds it.
set(LIBASN_GEN_DIR "${CMAKE_BINARY_DIR}/src/ipa/libasn/gen")
set(_libasn_stamp  "${CMAKE_BINARY_DIR}/src/ipa/libasn/libasn.stamp")
set(_asn_src_dir   "${CMAKE_CURRENT_SOURCE_DIR}/asn1")
set(_gen_script    "${_asn_src_dir}/gen_libasn.sh")
file(GLOB _asn_files "${_asn_src_dir}/*.asn")

find_program(ASN1C_EXECUTABLE asn1c)
if(NOT ASN1C_EXECUTABLE)
  message(FATAL_ERROR
    "asn1c not found -- install it (e.g. 'apt-get install asn1c') and re-run cmake.")
endif()

# Re-run cmake when a schema or the generator changes, so the staleness check
# below and the source glob in src/ipa/libasn/CMakeLists.txt re-evaluate.  This
# is what lets plain `make` pick up an edited .asn with no manual regen step.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${_asn_files} "${_gen_script}")

set(_need_gen FALSE)
if(NOT EXISTS "${_libasn_stamp}")
  set(_need_gen TRUE)  # never generated (e.g. a fresh checkout)
else()
  foreach(_f ${_asn_files} "${_gen_script}")
    if("${_f}" IS_NEWER_THAN "${_libasn_stamp}")
      set(_need_gen TRUE)  # a schema / the generator changed
    endif()
  endforeach()
endif()

if(_need_gen)
  message(STATUS "libasn: generating ASN.1 codec with ${ASN1C_EXECUTABLE}")
  execute_process(
    COMMAND bash "${_gen_script}" "${ASN1C_EXECUTABLE}" "${_asn_src_dir}" "${LIBASN_GEN_DIR}"
    RESULT_VARIABLE _gen_rc)
  if(NOT _gen_rc EQUAL 0)
    message(FATAL_ERROR "libasn generation failed (exit ${_gen_rc})")
  endif()
  file(TOUCH "${_libasn_stamp}")
else()
  message(STATUS "libasn: generated codec is up to date")
endif()
# ---------------------------------------------------------------------------

# asn1c API drift detection.  asn1c has diverged between tagged 0.9.28 and
# master in a few subtle ways that we can't fully hide at the .asn level.
# We detect each at configure time and set compile defines so libipa picks
# the right call form for whichever asn1c produced the generated tree.
set(_oid_header "${LIBASN_GEN_DIR}/OBJECT_IDENTIFIER.h")
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
set(_ct_header "${LIBASN_GEN_DIR}/constr_TYPE.h")
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
