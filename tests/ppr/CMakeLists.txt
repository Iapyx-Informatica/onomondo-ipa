# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(ppr_test ppr_test.c)
set_property(TARGET ppr_test PROPERTY C_STANDARD 99)
target_compile_options(ppr_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ppr_test libipa)
if (M32)
  set_target_properties(ppr_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME ppr_test
    COMMAND $<TARGET_FILE:ppr_test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
