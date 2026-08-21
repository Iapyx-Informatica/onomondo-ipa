# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(activation_code_test activation_code_test.c)
set_property(TARGET activation_code_test PROPERTY C_STANDARD 99)
target_compile_options(activation_code_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(activation_code_test libipa)
if (M32)
  set_target_properties(activation_code_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

# Output goes to this test's own binary directory, so the test holds for any
# build directory name and for a build tree outside the source tree.
add_test(NAME activation_code_test
    COMMAND sh -c "'$<TARGET_FILE:activation_code_test>' > activation_code_test.out 2> activation_code_test.err"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME activation_code_compare_stdout
    COMMAND ${CMAKE_COMMAND} -E compare_files
    ${CMAKE_CURRENT_BINARY_DIR}/activation_code_test.out
    ${CMAKE_CURRENT_SOURCE_DIR}/activation_code_test.ok)

add_test(NAME activation_code_compare_stderr
    COMMAND ${CMAKE_COMMAND} -E compare_files
    ${CMAKE_CURRENT_BINARY_DIR}/activation_code_test.err
    ${CMAKE_CURRENT_SOURCE_DIR}/activation_code_test.err)

# The comparisons read what the run above writes, so they must not be scheduled
# before it (ctest -j is free to reorder otherwise).
set_tests_properties(activation_code_test PROPERTIES FIXTURES_SETUP activation_code_output)
set_tests_properties(activation_code_compare_stdout activation_code_compare_stderr
    PROPERTIES FIXTURES_REQUIRED activation_code_output)
