// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// detect.hpp — Architecture capability detection.

#ifndef EAHCM_SIMD_DETECT_HPP
#define EAHCM_SIMD_DETECT_HPP

namespace eahcm {
namespace detail {
namespace simd {

/// Returns true if the host CPU and OS support executing AVX2 instructions safely.
bool cpu_supports_avx2() noexcept;

} // namespace simd
} // namespace detail
} // namespace eahcm

#endif // EAHCM_SIMD_DETECT_HPP
