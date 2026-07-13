# Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

add_subdirectory(libasn)
add_subdirectory(libipa)

# libasn is asn1c-generated code, and so is its CMakeLists.txt (see
# regenerate_libasn.sh) -- these settings therefore live here, where a
# regeneration cannot discard them.
#
# Its remaining warnings (structs declared inside parameter lists, unused
# variables) are generator artifacts we cannot fix without editing generated
# files. Build the target without warnings, and mark its headers SYSTEM so they
# stay quiet in the hand-written targets that include them too. Warnings in our
# own code remain visible: only libasn is exempted.
target_compile_options(libasn PRIVATE -w)
set_target_properties(libasn PROPERTIES
  INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/libasn")

find_package(OpenSSL REQUIRED)

add_library(http STATIC http.c)
add_library(scard STATIC scard.c)

target_include_directories(http PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_include_directories(scard PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(http PUBLIC OpenSSL::SSL OpenSSL::Crypto)

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
