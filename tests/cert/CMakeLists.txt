# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(cert_test cert_test.c)
set_property(TARGET cert_test PROPERTY C_STANDARD 99)
target_compile_options(cert_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(cert_test libipa)
if (M32)
  set_target_properties(cert_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME cert_test
    COMMAND $<TARGET_FILE:cert_test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
