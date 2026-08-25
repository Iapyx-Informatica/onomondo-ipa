# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(nvstate_test nvstate_test.c)
set_property(TARGET nvstate_test PROPERTY C_STANDARD 99)
target_compile_options(nvstate_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(nvstate_test libipa)
if (M32)
  set_target_properties(nvstate_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME nvstate_test
    COMMAND $<TARGET_FILE:nvstate_test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
