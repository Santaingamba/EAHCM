// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// config.hpp — Platform detection and compiler-specific configuration.
//
// This header is included by virtually every other EAHCM header.
// It must remain dependency-free (no other EAHCM headers, no STL beyond
// what's strictly needed for the macros below).
//
// Architecture notes
// ──────────────────
// 1. Compiler detection: defines EAHCM_COMPILER_{MSVC,GCC,CLANG} as 0/1.
//
// 2. 128-bit integer availability: defines EAHCM_HAS_UINT128 as 0/1.
//    Used in arithmetic.hpp to select the L() implementation path.
//
// 3. EAHCM_FORCE_INLINE: maps to __forceinline / always_inline / inline.
//
// 4. EAHCM_SECURE_ZERO(ptr, len): platform-secure memory wipe that is
//    guaranteed not to be optimised away by the compiler.
//    The three-branch fallback introduces the eahcm::detail namespace
//    with a single helper function (secure_zero_fallback).  This is the
//    only place where eahcm::detail is populated from a header rather
//    than from an implementation file.  The namespace is also used by
//    the internal HKDF helpers in detail/key_schedule_impl.hpp.
//
// 5. EAHCM_API: dllexport/dllimport/visibility for shared-library builds.
//    Static builds (the default) leave EAHCM_API empty.

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
// MSVC does not; we use split multiplication instead (see arithmetic.hpp).
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
//
// Three branches, in priority order:
//   1. MSVC: SecureZeroMemory() (Windows API, always available on MSVC)
//   2. C11 Annex K / Apple: memset_s()
//   3. Fallback: a volatile function-pointer call to std::memset — the
//      volatile prevents the compiler from proving the call is dead and
//      eliding it.  This approach is used by OpenSSL and BoringSSL.
//
// Architecture note: branch 3 introduces eahcm::detail::secure_zero_fallback
// inside this header.  This is the only EAHCM header that defines a symbol
// in eahcm::detail.  All other detail symbols are declared in sub-headers
// under include/eahcm/detail/ and implemented in src/.
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
