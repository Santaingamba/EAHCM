// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// vector_state.hpp — SIMD abstraction for EAHCM batch processing.
//
// Defines VectorState<W>, representing W independent EAHCM states running
// in parallel. A single VectorState cannot accelerate a single cipher stream
// due to the coupled nature of the mathematical recurrence. Instead, it
// accelerates deriving keystreams for W independent connections simultaneously.

#ifndef EAHCM_SIMD_VECTOR_STATE_HPP
#define EAHCM_SIMD_VECTOR_STATE_HPP

#include <cstdint>
#include <array>
#include "eahcm/state.hpp"

namespace eahcm {
namespace detail {
namespace simd {

/// Base template for vectorized states.
/// Specializations are defined in architecture-specific headers (avx2.hpp, neon.hpp).
template <size_t W>
struct VectorState;

} // namespace simd
} // namespace detail
} // namespace eahcm

#endif // EAHCM_SIMD_VECTOR_STATE_HPP
