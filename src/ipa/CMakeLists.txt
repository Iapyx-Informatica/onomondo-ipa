# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_subdirectory(libasn)
add_subdirectory(libipa)

add_library(http STATIC http.c)
add_library(scard STATIC scard.c)

target_include_directories(http PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_include_directories(scard PUBLIC ${CMAKE_SOURCE_DIR}/include)

if(APPLE)
  find_path(PCSC_INCLUDE_DIR NAMES winscard.h PATHS /opt/homebrew/opt/pcsc-lite/include/PCSC)
  include_directories(include ${PCSC_INCLUDE_DIR})
  find_library(PCSC_LIBRARY PCSC)
else()
  include_directories(include /usr/include/PCSC)
  set(PCSC_LIBRARY pcsclite)
endif()

add_executable(ipa main.c)
set_property(TARGET ipa PROPERTY C_STANDARD 99)
target_compile_options(ipa PRIVATE -Wall)

target_include_directories(ipa PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ipa libipa http scard ${PCSC_LIBRARY} curl)

if (M32)
  set_target_properties(http PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
  set_target_properties(scard PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
  set_target_properties(ipa PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()
