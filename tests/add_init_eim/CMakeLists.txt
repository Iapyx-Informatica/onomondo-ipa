# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(add_init_eim_test add_init_eim_test.c)
set_property(TARGET add_init_eim_test PROPERTY C_STANDARD 99)
target_compile_options(add_init_eim_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(add_init_eim_test libipa)
if (M32)
  set_target_properties(add_init_eim_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME add_init_eim_test
    COMMAND sh -c "$<TARGET_FILE:add_init_eim_test>")
