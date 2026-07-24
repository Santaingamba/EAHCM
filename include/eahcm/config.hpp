// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// config.hpp — Platform detection and compiler-specific configuration.

#ifndef EAHCM_CONFIG_HPP
#define EAHCM_CONFIG_HPP

// ---- Compiler detection ----
#if defined(_MSC_VER)
    #define EAHCM_COMPILER_MSVC 1
    #define EAHCM_COMPILER_GCC  0
    #define EAHCM_COMPILER_CLANG 0
#elif defined(__clang__)
    #define EAHCM_COMPILER_MSVC 0
    #define EAHCM_COMPILER_GCC  0
    #define EAHCM_COMPILER_CLANG 1
#elif defined(__GNUC__)
    #define EAHCM_COMPILER_MSVC 0
    #define EAHCM_COMPILER_GCC  1
    #define EAHCM_COMPILER_CLANG 0
#else
    #define EAHCM_COMPILER_MSVC 0
    #define EAHCM_COMPILER_GCC  0
    #define EAHCM_COMPILER_CLANG 0
#endif

// ---- 128-bit integer support ----
// GCC and Clang on 64-bit targets support __uint128_t.
// MSVC does not; we use split multiplication instead.
#if (EAHCM_COMPILER_GCC || EAHCM_COMPILER_CLANG) && (defined(__x86_64__) || defined(__aarch64__) || defined(__ppc64__))
    #define EAHCM_HAS_UINT128 1
#else
    #define EAHCM_HAS_UINT128 0
#endif

// ---- Force inline ----
#if EAHCM_COMPILER_MSVC
    #define EAHCM_FORCE_INLINE __forceinline
#elif EAHCM_COMPILER_GCC || EAHCM_COMPILER_CLANG
    #define EAHCM_FORCE_INLINE __attribute__((always_inline)) inline
#else
    #define EAHCM_FORCE_INLINE inline
#endif

// ---- Secure memory zeroing ----
// Platform-specific secure wipe that won't be optimised away.
#if EAHCM_COMPILER_MSVC
    #include <windows.h>
    #define EAHCM_SECURE_ZERO(ptr, len) SecureZeroMemory((ptr), (len))
#elif defined(__STDC_LIB_EXT1__) || defined(__APPLE__)
    #include <string.h>
    #define EAHCM_SECURE_ZERO(ptr, len) memset_s((ptr), (len), 0, (len))
#else
    // Fallback: volatile function pointer prevents optimisation.
    #include <cstring>
    namespace eahcm::detail {
        inline void secure_zero_fallback(void* ptr, std::size_t len) noexcept {
            static void* (*volatile memset_ptr)(void*, int, std::size_t) = std::memset;
            memset_ptr(ptr, 0, len);
        }
    } // namespace eahcm::detail
    #define EAHCM_SECURE_ZERO(ptr, len) ::eahcm::detail::secure_zero_fallback((ptr), (len))
#endif

// ---- Export/import macros for shared library ----
//
// When building EAHCM as a shared library (.dll / .so / .dylib):
//   1. The CMake build system defines both EAHCM_SHARED_LIBRARY and
//      EAHCM_BUILDING_LIBRARY automatically (see root CMakeLists.txt).
//   2. This causes EAHCM_API to expand to dllexport (MSVC) or
//      visibility("default") (GCC/Clang), marking public symbols.
//
// When consuming EAHCM as a shared library from another project:
//   - Define EAHCM_SHARED_LIBRARY but NOT EAHCM_BUILDING_LIBRARY.
//   - This causes EAHCM_API to expand to dllimport (MSVC) or
//     visibility("default") (GCC/Clang).
//
// When building/consuming as a static library (the default):
//   - Neither macro is defined. EAHCM_API expands to nothing.
//
#if defined(EAHCM_SHARED_LIBRARY)
    #if EAHCM_COMPILER_MSVC
        #if defined(EAHCM_BUILDING_LIBRARY)
            #define EAHCM_API __declspec(dllexport)
        #else
            #define EAHCM_API __declspec(dllimport)
        #endif
    #elif EAHCM_COMPILER_GCC || EAHCM_COMPILER_CLANG
        #define EAHCM_API __attribute__((visibility("default")))
    #else
        #define EAHCM_API
    #endif
#else
    #define EAHCM_API
#endif

#endif // EAHCM_CONFIG_HPP
