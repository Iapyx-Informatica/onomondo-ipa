# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(eim_pkg_result_der_test eim_pkg_result_der_test.c)
set_property(TARGET eim_pkg_result_der_test PROPERTY C_STANDARD 99)
target_compile_options(eim_pkg_result_der_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(eim_pkg_result_der_test libipa)
if (M32)
  set_target_properties(eim_pkg_result_der_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME eim_pkg_result_der_test
    COMMAND $<TARGET_FILE:eim_pkg_result_der_test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
