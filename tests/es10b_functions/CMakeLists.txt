# Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

# These drive the real ES10b path, which every build has: IPA_EUICC_EMU() folds to a constant 0 without
# the emulation, so the two functions that have an emulation branch take the real one here whatever the
# build options say.  The emulation branches themselves are covered in tests/euicc_emu/.
add_executable(es10b_functions_test es10b_functions_test.c ${PROJECT_SOURCE_DIR}/tests/stubs/euicc_stub.c)
set_property(TARGET es10b_functions_test PROPERTY C_STANDARD 99)
target_compile_options(es10b_functions_test PRIVATE -Wall)
target_compile_definitions(es10b_functions_test PRIVATE _GNU_SOURCE)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(es10b_functions_test libipa)
if (M32)
  set_target_properties(es10b_functions_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_test(NAME es10b_functions_test
    COMMAND $<TARGET_FILE:es10b_functions_test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
