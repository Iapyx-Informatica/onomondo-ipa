# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

enable_testing()

add_subdirectory(activation_code)
add_subdirectory(utils)
add_subdirectory(bpp_segments)
add_subdirectory(ipa_capabilities)
add_subdirectory(cert)
add_subdirectory(ppr)
add_subdirectory(profile_info)
add_subdirectory(add_init_eim)
add_subdirectory(euicc_pkg_notif)
add_subdirectory(esipa_bindings)
add_subdirectory(eim_pkg_result_der)
add_subdirectory(device_info)
add_subdirectory(log)
add_subdirectory(build_options)
add_subdirectory(es10b_functions)
add_subdirectory(euicc_emu)
add_subdirectory(nvstate)
add_subdirectory(cr_markers)
