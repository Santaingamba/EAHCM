// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bit_ops.hpp — Bit manipulation primitives for the EAHCM cipher.
//
// Contains the 32-bit left rotation (ROL32) which is used by every
// component of the cipher: state equations, parameter drift, and
// keystream extraction.

#ifndef EAHCM_BIT_OPS_HPP
#define EAHCM_BIT_OPS_HPP

#include <cstdint>

#include "eahcm/config.hpp"

namespace eahcm {

/// 32-bit left rotation.
///
/// Rotates `x` left by `n` positions.
/// Precondition: 1 <= n <= 31 (all rotation constants in EAHCM satisfy this).
///
/// This form is recognized by all major compilers (GCC, Clang, MSVC)
/// and compiled to a single ROL instruction on x86.
///
/// No UB: both shifts operate on uint32_t, and n is always in [1, 31].
///
/// @param x  The 32-bit word to rotate.
/// @param n  The rotation amount (must be in [1, 31]).
/// @return   The rotated result.
[[nodiscard]] EAHCM_FORCE_INLINE constexpr std::uint32_t
rol32(std::uint32_t x, int n) noexcept {
    return (x << n) | (x >> (32 - n));
}

} // namespace eahcm

#endif // EAHCM_BIT_OPS_HPP
