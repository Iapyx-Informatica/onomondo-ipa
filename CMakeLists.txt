# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.13...3.19 FATAL_ERROR)
project(ipa VERSION 0.0.1 LANGUAGES C)

option(ENABLE_SANITIZE "Compile with address sanitizer enabled" OFF)
option(SHOW_ASN_OUTPUT "Show ASN.1 decoded output in the log" OFF)
option(ASN_EMIT_DEBUG "Enable built-in debug output of asn1c" OFF)
option(MEM_EMIT_DEBUG "Enable debug output for heap memory usage" OFF)
option(M32 "Compile for 32 bit mode" OFF)
option(CERT_ALLOW_UNSET_CLOCK "Skip the certificate validity period check when the system clock is not set" OFF)
option(PPR_ALLOW_WITHOUT_CONSENT "Install profiles whose policy rules need end user consent even when no consent callback is registered" OFF)
option(IOT_EUICC_EMULATION "Build the IoT eUICC emulation, which lets a consumer (SGP.22) eUICC be used in place of an IoT (SGP.32) one" OFF)
option(ESIPA_BINDING_ASN1 "Build the ESipa ASN.1 wire binding (SGP.32 section 6.3)" ON)
option(ESIPA_BINDING_JSON "Build the ESipa JSON wire binding (SGP.32 section 6.4, requires jansson)" ON)

if (ENABLE_SANITIZE)
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif()

# Link-time dead code elimination.  Without this the linker works at object-file
# granularity, and asn1c puts a type's whole codec set into one object: asking
# for SEQUENCE_decode_ber drags in SEQUENCE_decode_xer and SEQUENCE_print with
# it, whether or not anything can reach them.  One section per function and per
# datum lets the linker drop what is unreachable instead, which is what makes
# the codec trimming below (and the optional features above) actually shrink the
# image rather than merely stop being called.
if(APPLE)
  add_compile_options(-ffunction-sections -fdata-sections)
  add_link_options(-Wl,-dead_strip)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-ffunction-sections -fdata-sections)
  add_link_options(-Wl,--gc-sections)
else()
  message(STATUS "unknown compiler ${CMAKE_C_COMPILER_ID}: building without link-time dead code elimination")
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

# The validity period of a certificate can only be judged against a clock that can be trusted, and an IPA that boots
# without a battery-backed RTC has none until it has IP connectivity -- which it cannot have before it is
# provisioned. Such a build has to skip the check rather than fail it, or the device can never provision itself.
# That is a real weakening (an attacker who keeps the clock unset also keeps the check away), so it is not the
# default: everywhere else an unusable clock fails the check. See src/ipa/libipa/cert.c.
if(CERT_ALLOW_UNSET_CLOCK)
  message(STATUS "certificate validity: an unset system clock SKIPS the check (build for a device without an RTC)")
  add_definitions(-DCERT_ALLOW_UNSET_CLOCK)
else()
  message(STATUS "certificate validity: an unset system clock FAILS the check "
                 "(-DCERT_ALLOW_UNSET_CLOCK=ON for a device without an RTC)")
endif()

# The Rules Authorisation Table of an eUICC can mark a Profile Policy Rule as requiring the consent of the end user.
# A device with a user interface answers that by registering ipa_config.ppr_consent_cb and asking. A device without
# one has nobody to ask, and this option decides what it does instead: refuse the profile (the default) or install
# it as if consent had been given. See src/ipa/libipa/ppr.c.
if(PPR_ALLOW_WITHOUT_CONSENT)
  message(STATUS "profile policy rules: consent that cannot be asked for is ASSUMED GRANTED (build for a device without a user interface)")
  add_definitions(-DPPR_ALLOW_WITHOUT_CONSENT)
else()
  message(STATUS "profile policy rules: consent that cannot be asked for REFUSES the profile "
                 "(-DPPR_ALLOW_WITHOUT_CONSENT=ON to install it anyway)")
endif()

# The IoT eUICC emulation adapts a consumer (SGP.22) eUICC on ES10x level so that it looks like an IoT (SGP.32)
# eUICC to everything above.  It is off by default: a product ships with the eUICC it ships with, and a build that
# will never see a consumer card should not carry the adaptation layer.  See README.md and ipa_config.iot_euicc_emu_enabled.
if(IOT_EUICC_EMULATION)
  message(STATUS "IoT eUICC emulation: BUILT (consumer eUICCs can be used, enable at runtime with -E)")
else()
  message(STATUS "IoT eUICC emulation: NOT built "
                 "(-DIOT_EUICC_EMULATION=ON to support consumer eUICCs)")
endif()

# The two ESipa wire bindings of SGP.32 v1.2.  Both are built by default; a deployment that knows which one its eIM
# speaks can drop the other.  At least one has to remain, or the IPA cannot talk to an eIM at all.
if(NOT ESIPA_BINDING_ASN1 AND NOT ESIPA_BINDING_JSON)
  message(FATAL_ERROR
    "ESIPA_BINDING_ASN1 and ESIPA_BINDING_JSON are both OFF: the IPA would have no way to reach an eIM. "
    "Enable at least one.")
endif()
if(ESIPA_BINDING_ASN1)
  message(STATUS "ESipa binding ASN.1 (section 6.3): built")
else()
  message(STATUS "ESipa binding ASN.1 (section 6.3): NOT built")
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

# Which codecs the generated tree is asked to carry.  asn1c wires every type to a full set -- BER/DER, XER, and a
# printer -- but this project decodes and encodes DER only, and the printer is reachable solely through
# SHOW_ASN_OUTPUT.  The generator drops what is not asked for; see asn1/gen_libasn.sh.  The profile is part of the
# staleness check because changing it changes the generated sources just as editing a schema would.
if(SHOW_ASN_OUTPUT)
  set(_libasn_keep_print 1)
else()
  set(_libasn_keep_print 0)
endif()
set(_libasn_profile "print=${_libasn_keep_print}")
set(_libasn_profile_file "${CMAKE_BINARY_DIR}/src/ipa/libasn/libasn.profile")
set(_libasn_profile_prev "")
if(EXISTS "${_libasn_profile_file}")
  file(READ "${_libasn_profile_file}" _libasn_profile_prev)
endif()

set(_need_gen FALSE)
if(NOT EXISTS "${_libasn_stamp}")
  set(_need_gen TRUE)  # never generated (e.g. a fresh checkout)
else()
  foreach(_f ${_asn_files} "${_gen_script}")
    if("${_f}" IS_NEWER_THAN "${_libasn_stamp}")
      set(_need_gen TRUE)  # a schema / the generator changed
    endif()
  endforeach()
  if(NOT _libasn_profile STREQUAL _libasn_profile_prev)
    set(_need_gen TRUE)  # a different set of codecs is wanted
  endif()
endif()

if(_need_gen)
  message(STATUS "libasn: generating ASN.1 codec with ${ASN1C_EXECUTABLE}")
  execute_process(
    COMMAND bash "${_gen_script}" "${ASN1C_EXECUTABLE}" "${_asn_src_dir}" "${LIBASN_GEN_DIR}"
            "${_libasn_keep_print}"
    RESULT_VARIABLE _gen_rc)
  if(NOT _gen_rc EQUAL 0)
    message(FATAL_ERROR "libasn generation failed (exit ${_gen_rc})")
  endif()
  file(TOUCH "${_libasn_stamp}")
  file(WRITE "${_libasn_profile_file}" "${_libasn_profile}")
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
