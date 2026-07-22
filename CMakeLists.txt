# SPDX-License-Identifier: MIT
# EAHCM — Root CMakeLists.txt
# Production-quality C++ reference implementation of the EAHCM cipher.

cmake_minimum_required(VERSION 3.20)

project(EAHCM
    VERSION 1.0.0
    DESCRIPTION "EAHCM 4D Chaotic Cipher — Official C++ Reference Implementation"
    HOMEPAGE_URL "https://github.com/eahcm/eahcm"
    LANGUAGES CXX
)

# ---- C++ Standard ----
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Options ----
option(EAHCM_BUILD_TESTS       "Build test suite"           ON)
option(EAHCM_BUILD_BENCHMARKS  "Build benchmarks"           OFF)
option(EAHCM_BUILD_EXAMPLES    "Build examples"             ON)
option(EAHCM_BUILD_SHARED      "Build as shared library"    OFF)
option(EAHCM_ENABLE_SANITIZERS "Enable ASan/UBSan"          OFF)
option(EAHCM_WARNINGS_AS_ERRORS "Treat warnings as errors"  ON)

# ---- Compiler warnings ----
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wno-sign-conversion)
    if(EAHCM_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /permissive-)
    if(EAHCM_WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif()
endif()

# ---- Sanitizers ----
if(EAHCM_ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# ---- Find OpenSSL ----
find_package(OpenSSL REQUIRED)

# ---- Library target ----
set(EAHCM_SOURCES
    src/key_schedule.cpp
    src/cipher.cpp
    src/serialization.cpp
)

if(EAHCM_BUILD_SHARED)
    add_library(eahcm SHARED ${EAHCM_SOURCES})
    target_compile_definitions(eahcm
        PRIVATE EAHCM_BUILDING_LIBRARY EAHCM_SHARED_LIBRARY
    )
else()
    add_library(eahcm STATIC ${EAHCM_SOURCES})
endif()

add_library(EAHCM::eahcm ALIAS eahcm)

target_include_directories(eahcm
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(eahcm
    PUBLIC OpenSSL::Crypto
)

target_compile_features(eahcm PUBLIC cxx_std_20)

set_target_properties(eahcm PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME eahcm
)

# ---- Install ----
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS eahcm
    EXPORT EAHCMTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/eahcm
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT EAHCMTargets
    FILE EAHCMTargets.cmake
    NAMESPACE EAHCM::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EAHCM
)

configure_package_config_file(
    cmake/EAHCMConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/EAHCMConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EAHCM
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/EAHCMConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/EAHCMConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/EAHCMConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EAHCM
)

# ---- Tests ----
if(EAHCM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---- Examples ----
if(EAHCM_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---- Benchmarks ----
if(EAHCM_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# ---- CPack ----
set(CPACK_PACKAGE_NAME "EAHCM")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VENDOR "EAHCM Authors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
include(CPack)
