// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// constants.hpp — Frozen mathematical constants for the EAHCM cipher.
//
// These values are immutable. They match the Python reference implementation
// exactly and must NEVER be modified.

#ifndef EAHCM_CONSTANTS_HPP
#define EAHCM_CONSTANTS_HPP

#include <cstdint>

namespace eahcm {

/// 32-bit mask — enforces uint32 wrapping (automatic in C++ for uint32_t).
inline constexpr std::uint32_t MASK32 = 0xFFFF'FFFFu;

/// Fractional bits of pi — nothing-up-my-sleeve constant for epsilon injection.
inline constexpr std::uint32_t PI_FRAC = 0x243F'6A88u;

/// Fractional bits of phi (golden ratio) — fixed-point guard in F().
inline constexpr std::uint32_t PHI_FRAC = 0x9E37'79B9u;

/// Epsilon perturbation constant (== PI_FRAC, Flaw 5 fix).
inline constexpr std::uint32_t EPSILON_CONST = 0x243F'6A88u;

/// Lower bound for chaotic parameters (deep chaotic regime).
inline constexpr std::uint32_t PARAM_FLOOR = 0xE000'0000u;

/// Parameter drift range width: PARAM_CEILING - PARAM_FLOOR.
inline constexpr std::uint32_t DRIFT_MASK = 0x1FF0'0000u;

/// Upper bound for chaotic parameters.
inline constexpr std::uint32_t PARAM_CEILING = PARAM_FLOOR + DRIFT_MASK;

/// Number of steps between parameter re-parameterisations.
inline constexpr std::uint32_t DRIFT_INTERVAL = 64u;

/// Mandatory warmup iterations before keystream extraction.
inline constexpr std::uint32_t WARMUP_STEPS = 256u;

/// Additional post-hash-mixing warmup iterations.
inline constexpr std::uint32_t POST_HASH_STEPS = 64u;

/// Sentinel replacement for absorbing state v == 0x00000000.
inline constexpr std::uint32_t SENTINEL_ZERO = 0xDEAD'BEEFu;

/// Sentinel replacement for absorbing state v == 0xFFFFFFFF.
inline constexpr std::uint32_t SENTINEL_ONES = 0x1337'1337u;

// ---- Rotation constants (frozen) ----
// State equations
inline constexpr int ROT_Y_IN_X  = 11;  // ROL32(y, 11) in x equation
inline constexpr int ROT_X_IN_Y  = 17;  // ROL32(x, 17) in y equation
inline constexpr int ROT_W_IN_Z  = 23;  // ROL32(w, 23) in z equation
inline constexpr int ROT_Z_IN_W  = 31;  // ROL32(z, 31) in w equation
inline constexpr int ROT_CTR_EPS =  5;  // ROL32(counter, 5) in epsilon

// Parameter drift
inline constexpr int ROT_DRIFT_ALPHA =  3;
inline constexpr int ROT_DRIFT_GAMMA = 11;
inline constexpr int ROT_DRIFT_MU    = 19;
inline constexpr int ROT_DRIFT_SIGMA = 27;

// Extraction
inline constexpr int ROT_EXTRACT = 16;  // ROL32(y, 16) and ROL32(x, 16)

} // namespace eahcm

#endif // EAHCM_CONSTANTS_HPP
