# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

# The IoT eUICC emulation is what this exercises, so there is nothing to run without it.
if (NOT IOT_EUICC_EMULATION)
  return()
endif()

add_executable(euicc_emu_test euicc_emu_test.c ${PROJECT_SOURCE_DIR}/tests/stubs/euicc_stub.c)
set_property(TARGET euicc_emu_test PROPERTY C_STANDARD 99)
target_compile_options(euicc_emu_test PRIVATE -Wall)
target_compile_definitions(euicc_emu_test PRIVATE _GNU_SOURCE)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(euicc_emu_test libipa)
if (M32)
  set_target_properties(euicc_emu_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME euicc_emu_test
    COMMAND $<TARGET_FILE:euicc_emu_test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
