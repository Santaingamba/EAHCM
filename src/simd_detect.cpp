// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors

#include "eahcm/detail/simd/detect.hpp"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace eahcm {
namespace detail {
namespace simd {

bool cpu_supports_avx2() noexcept {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    if (cpuInfo[0] < 7) {
        return false; // Leaf 7 not supported
    }

    __cpuid(cpuInfo, 1);
    bool osxsave = (cpuInfo[2] & (1 << 27)) != 0;
    bool avx = (cpuInfo[2] & (1 << 28)) != 0;
    if (!osxsave || !avx) {
        return false;
    }

    // Check XGETBV to see if OS saves XMM and YMM state (bits 1 and 2)
    unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
    if ((xcrFeatureMask & 0x6) != 0x6) {
        return false;
    }

    // Check AVX2 support in leaf 7
    __cpuidex(cpuInfo, 7, 0);
    bool avx2 = (cpuInfo[1] & (1 << 5)) != 0;
    return avx2;
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") > 0;
#else
    return false;
#endif
}

} // namespace simd
} // namespace detail
} // namespace eahcm
