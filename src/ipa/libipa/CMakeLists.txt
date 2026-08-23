# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_library(libipa STATIC
  activation_code.c
  bpp_segments.c
  cert.c
  device_info.c
  esipa_json.c
  es10a_get_euicc_cfg_addr.c
  es10b_add_init_eim.c
  es10b_auth_serv.c
  es10b_cancel_session.c
  es10b_euicc_mem_rst.c
  es10b_get_certs.c
  es10b_get_eim_cfg_data.c
  es10b_get_euicc_chlg.c
  es10b_get_euicc_info.c
  es10b_get_rat.c
  es10b_load_bnd_prfle_pkg.c
  es10b_load_euicc_pkg.c
  es10b_prep_dwnld.c
  es10b_prfle_rollback.c
  es10b_retr_notif_from_lst.c
  es10b_rm_notif_from_lst.c
  es10c_delete_prfle.c
  es10c_disable_prfle.c
  es10c_enable_prfle.c
  es10b_immediate_enable.c
  es10b_execute_fallback.c
  ipae_activation.c
  es10b_cfg_immediate_enable.c
  es10b_return_from_fallback.c
  es10b_enable_emergency_profile.c
  es10b_disable_emergency_profile.c
  es10b_get_connectivity_params.c
  es10b_set_default_dp_addr.c
  es10c_get_eid.c
  es10c_get_prfle_info.c
  es10x.c
  esipa_auth_clnt.c
  esipa.c
  esipa_cancel_session.c
  esipa_get_bnd_prfle_pkg.c
  esipa_get_eim_pkg.c
  esipa_handle_notif.c
  esipa_init_auth.c
  esipa_prvde_eim_pkg_rslt.c
  euicc.c
  ipad.c
  log.c
  ppr.c
  proc_cmn_cancel_sess.c
  proc_cmn_mtl_auth.c
  proc_indirect_prfle_dwnld.c
  proc_eim_pkg_retr.c
  proc_euicc_data_req.c
  proc_euicc_pkg_dwnld_exec.c
  proc_notif_delivery.c
  proc_prfle_dwnld.c
  proc_prfle_inst.c
  utils.c
)

target_include_directories(libipa PUBLIC ${CMAKE_SOURCE_DIR}/include PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(libipa PUBLIC libasn)
target_compile_options(libipa PRIVATE -Wall)

# The IoT eUICC emulation (see the top-level CMakeLists.txt).  PUBLIC because the sample application, the tests and
# any other consumer of libipa have to agree with the library about whether the emulation exists -- ipa_config keeps
# the runtime flag either way, so the difference is not visible in the struct layout.
if(IOT_EUICC_EMULATION)
  target_compile_definitions(libipa PUBLIC IPA_HAVE_IOT_EUICC_EMULATION=1)
endif()

# The two ESipa wire bindings (see the top-level CMakeLists.txt for the options).  PUBLIC, because the sample
# application, the tests and any other consumer have to agree with the library about which bindings exist.
if(ESIPA_BINDING_ASN1)
  target_compile_definitions(libipa PUBLIC IPA_HAVE_ESIPA_ASN1=1)
endif()

# The JSON binding needs jansson.  ESIPA_BINDING_JSON is ON by default, and when it is on the dependency is a hard
# requirement: silently degrading to an ASN.1-only library because the build host happened not to have
# libjansson-dev is how two machines end up producing two different libipa from the same source.
if(ESIPA_BINDING_JSON)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(JANSSON QUIET jansson)
  endif()
  if(NOT JANSSON_FOUND)
    message(FATAL_ERROR
      "ESipa binding JSON (section 6.4) is enabled but jansson was not found. "
      "Install it (e.g. 'apt-get install libjansson-dev'), or build without the JSON binding "
      "by passing -DESIPA_BINDING_JSON=OFF.")
  endif()
  message(STATUS "ESipa binding JSON (section 6.4): built (jansson ${JANSSON_VERSION})")
  target_compile_definitions(libipa PUBLIC IPA_HAVE_ESIPA_JSON=1)
  target_include_directories(libipa PRIVATE ${JANSSON_INCLUDE_DIRS})
  target_link_libraries(libipa PUBLIC ${JANSSON_LIBRARIES})
  target_link_directories(libipa PUBLIC ${JANSSON_LIBRARY_DIRS})
else()
  message(STATUS "ESipa binding JSON (section 6.4): NOT built")
endif()
if (M32)
  set_target_properties(libipa PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()
