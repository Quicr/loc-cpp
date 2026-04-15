cmake_minimum_required(VERSION 3.24)

project(
  loc
  VERSION 0.2.0
  DESCRIPTION "Modern C++20 LOC (Low Overhead Media Container) implementation"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(LOC_BUILD_TESTS "Build unit and integration tests" OFF)
option(LOC_BUILD_EXAMPLES "Build examples" OFF)
option(LOC_BUILD_BENCHMARKS "Build benchmarks" OFF)
option(LOC_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(LOC_USE_MOQ_VARINT "Use MOQ varint encoding instead of QUIC" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)

# Header-only library
add_library(loc INTERFACE)
add_library(loc::loc ALIAS loc)

target_include_directories(loc
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

target_compile_features(loc INTERFACE cxx_std_20)

if(LOC_USE_MOQ_VARINT)
  target_compile_definitions(loc INTERFACE LOC_USE_MOQ_VARINT=1)
endif()

# Compiler warnings
target_compile_options(loc INTERFACE
  $<$<COMPILE_LANG_AND_ID:CXX,AppleClang,Clang,GNU>:
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast>
  $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/W4 /permissive->)

if(LOC_WARNINGS_AS_ERRORS)
  target_compile_options(loc INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,AppleClang,Clang,GNU>:-Werror>
    $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/WX>)
endif()

# Installation
install(
  DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  TARGETS loc
  EXPORT locTargets)

install(
  EXPORT locTargets
  FILE locTargets.cmake
  NAMESPACE loc::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/loc)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/locConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/locConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/locConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/loc)

install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/locConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/locConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/loc)

# Tests
if(LOC_BUILD_TESTS)
  add_library(loc_doctest INTERFACE)
  target_include_directories(loc_doctest INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

  add_executable(loc_unit_tests
    tests/test_main.cpp
    tests/varint_tests.cpp
    tests/property_tests.cpp
    tests/object_tests.cpp)
  target_link_libraries(loc_unit_tests PRIVATE loc::loc loc_doctest)
  add_test(NAME loc_unit_tests COMMAND loc_unit_tests)

  add_executable(loc_integration_tests
    tests/test_main.cpp
    tests/integration/roundtrip_tests.cpp)
  target_link_libraries(loc_integration_tests PRIVATE loc::loc loc_doctest)
  add_test(NAME loc_integration_tests COMMAND loc_integration_tests)
endif()

# Examples
if(LOC_BUILD_EXAMPLES)
  add_executable(loc_example examples/loc_example.cpp)
  target_link_libraries(loc_example PRIVATE loc::loc)
endif()

# Benchmarks
if(LOC_BUILD_BENCHMARKS)
  add_executable(loc_benchmark tests/bench/benchmark.cpp)
  target_link_libraries(loc_benchmark PRIVATE loc::loc)
  target_compile_options(loc_benchmark PRIVATE -O3)
endif()
