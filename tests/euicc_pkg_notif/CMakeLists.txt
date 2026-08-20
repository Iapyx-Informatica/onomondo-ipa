# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(euicc_pkg_notif_test euicc_pkg_notif_test.c)
set_property(TARGET euicc_pkg_notif_test PROPERTY C_STANDARD 99)
target_compile_options(euicc_pkg_notif_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(euicc_pkg_notif_test libipa)
if (M32)
  set_target_properties(euicc_pkg_notif_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME euicc_pkg_notif_test
    COMMAND sh -c "$<TARGET_FILE:euicc_pkg_notif_test>")
