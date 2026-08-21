# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(ipa_capabilities_test ipa_capabilities_test.c)
set_property(TARGET ipa_capabilities_test PROPERTY C_STANDARD 99)
target_compile_options(ipa_capabilities_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ipa_capabilities_test libipa)
if (M32)
  set_target_properties(ipa_capabilities_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

# Output goes to this test's own binary directory, so the test holds for any
# build directory name and for a build tree outside the source tree.
add_test(NAME ipa_capabilities_test
    COMMAND sh -c "'$<TARGET_FILE:ipa_capabilities_test>' > ipa_capabilities_test.out 2> ipa_capabilities_test.err"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME ipa_capabilities_compare_stdout
    COMMAND ${CMAKE_COMMAND} -E compare_files
    ${CMAKE_CURRENT_BINARY_DIR}/ipa_capabilities_test.out
    ${CMAKE_CURRENT_SOURCE_DIR}/ipa_capabilities_test.ok)

# The comparison reads what the run above writes, so it must not be scheduled
# before it (ctest -j is free to reorder otherwise).
set_tests_properties(ipa_capabilities_test PROPERTIES FIXTURES_SETUP ipa_capabilities_output)
set_tests_properties(ipa_capabilities_compare_stdout PROPERTIES FIXTURES_REQUIRED ipa_capabilities_output)
