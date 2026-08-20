# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(esipa_json_test esipa_json_test.c)
set_property(TARGET esipa_json_test PROPERTY C_STANDARD 99)
target_compile_options(esipa_json_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(esipa_json_test libipa)
if (M32)
  set_target_properties(esipa_json_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME esipa_json_test
    COMMAND sh -c "$<TARGET_FILE:esipa_json_test>")
