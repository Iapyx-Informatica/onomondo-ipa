# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(bpp_segments_test bpp_segments_test.c)
set_property(TARGET bpp_segments_test PROPERTY C_STANDARD 99)
target_compile_options(bpp_segments_test PRIVATE -Wall)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(bpp_segments_test libipa)
if (M32)
  set_target_properties(bpp_segments_test PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

# The input is read from the source tree and the output written to this test's
# own binary directory, so the test holds for any build directory name and for
# a build tree outside the source tree.
#
# The "====>" lines the -DMEM_EMIT_DEBUG=ON allocation tracer writes to stderr are stripped from both
# captured streams before the comparisons below read them.  See tests/activation_code/CMakeLists.txt.
add_test(NAME bpp_segments_test
    COMMAND sh -c "'$<TARGET_FILE:bpp_segments_test>' '${CMAKE_CURRENT_SOURCE_DIR}/bpp.ber' > raw.out 2> raw.err; rc=$?; \
                   sed '/^====>/d' raw.out > bpp_segments_test.out; \
                   sed '/^====>/d' raw.err > bpp_segments_test.err; \
                   exit $rc"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME bpp_segments_compare_stdout
    COMMAND ${CMAKE_COMMAND} -E compare_files
    ${CMAKE_CURRENT_BINARY_DIR}/bpp_segments_test.out
    ${CMAKE_CURRENT_SOURCE_DIR}/bpp_segments_test.ok)

add_test(NAME bpp_segments_compare_stderr
    COMMAND ${CMAKE_COMMAND} -E compare_files
    ${CMAKE_CURRENT_BINARY_DIR}/bpp_segments_test.err
    ${CMAKE_CURRENT_SOURCE_DIR}/bpp_segments_test.err)

# The comparisons read what the run above writes, so they must not be scheduled
# before it (ctest -j is free to reorder otherwise).
set_tests_properties(bpp_segments_test PROPERTIES FIXTURES_SETUP bpp_segments_output)
set_tests_properties(bpp_segments_compare_stdout bpp_segments_compare_stderr
    PROPERTIES FIXTURES_REQUIRED bpp_segments_output)
