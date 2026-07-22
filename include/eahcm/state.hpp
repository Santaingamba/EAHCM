// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// state.hpp — EAHCM 4D chaotic state machine.
//
// Implements the full state update (step), parameter drift, and
// keystream extraction, exactly matching the Python EAHCMState class.

#ifndef EAHCM_STATE_HPP
#define EAHCM_STATE_HPP

#include <cstdint>
#include <array>

#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"
#include "eahcm/types.hpp"
#include "eahcm/arithmetic.hpp"
#include "eahcm/bit_ops.hpp"

namespace eahcm {

/// Clamp a raw 32-bit parameter value into the chaotic regime.
///
/// Formula: PARAM_FLOOR + (raw % DRIFT_MASK)
///
/// This matches the Python EAHCMState._clamp() and key_schedule._clamp_param().
[[nodiscard]] EAHCM_FORCE_INLINE constexpr std::uint32_t
clamp_param(std::uint32_t raw) noexcept {
    return PARAM_FLOOR + (raw % DRIFT_MASK);
}

/// Replace absorbing-state values with safe sentinels.
///
/// v == 0x00000000  →  0xDEADBEEF
/// v == 0xFFFFFFFF  →  0x13371337
///
/// These values cause v * ~v = 0 in L(), creating a permanent zero sink.
[[nodiscard]] EAHCM_FORCE_INLINE constexpr std::uint32_t
guard_absorbing(std::uint32_t v) noexcept {
    if (v == 0x0000'0000u) return SENTINEL_ZERO;
    if (v == 0xFFFF'FFFFu) return SENTINEL_ONES;
    return v;
}

/// Initialize a State from raw values.
///
/// Applies:
///   1. Mask state variables to 32 bits (automatic for uint32_t)
///   2. Clamp parameters into the chaotic regime
///   3. Guard absorbing states in the initial condition
///   4. Set counter to zero
///
/// This exactly matches the Python EAHCMState.__init__().
[[nodiscard]] inline constexpr State
make_state(std::uint32_t x, std::uint32_t y,
           std::uint32_t z, std::uint32_t w,
           std::uint32_t alpha, std::uint32_t gamma,
           std::uint32_t mu, std::uint32_t sigma) noexcept {
    State s;
    s.x = x;
    s.y = y;
    s.z = z;
    s.w = w;
    s.alpha = clamp_param(alpha);
    s.gamma = clamp_param(gamma);
    s.mu    = clamp_param(mu);
    s.sigma = clamp_param(sigma);
    s.counter = 0;

    // Guard absorbing states AFTER masking
    s.x = guard_absorbing(s.x);
    s.y = guard_absorbing(s.y);
    s.z = guard_absorbing(s.z);
    s.w = guard_absorbing(s.w);

    return s;
}

/// Perform parameter drift on a State.
///
/// Called every DRIFT_INTERVAL steps. Uses the XOR-fold of the
/// PRE-step state values (x_prev, y_prev, z_prev, w_prev).
///
/// Each parameter is XOR-folded with the state at different rotation
/// amounts (3, 11, 19, 27), then clamped back into the chaotic regime.
///
/// Exactly matches Python EAHCMState._drift_parameters().
inline constexpr void
drift_parameters(State& s,
                 std::uint32_t x_prev, std::uint32_t y_prev,
                 std::uint32_t z_prev, std::uint32_t w_prev) noexcept {
    const std::uint32_t fold = x_prev ^ y_prev ^ z_prev ^ w_prev;

    s.alpha = clamp_param(s.alpha ^ rol32(fold, ROT_DRIFT_ALPHA));
    s.gamma = clamp_param(s.gamma ^ rol32(fold, ROT_DRIFT_GAMMA));
    s.mu    = clamp_param(s.mu    ^ rol32(fold, ROT_DRIFT_MU));
    s.sigma = clamp_param(s.sigma ^ rol32(fold, ROT_DRIFT_SIGMA));
}

/// Advance the 4D chaotic state by one iteration.
///
/// ALL FOUR reads happen before ANY write — this is mandatory.
/// The epsilon injection (Flaw 5 fix) is a lightweight, non-repeating
/// perturbation derived from the step counter.
///
/// State equations (all arithmetic wraps mod 2^32):
///   x_{n+1} = L(x_n, α_n) + ( F(z_n) XOR ROL32(y_n, 11) ) + ε_n
///   y_{n+1} = L(y_n, γ_n) + ( R(w_n) XOR ROL32(x_n, 17) )
///   z_{n+1} = L(z_n, μ_n) + ( F(x_n) XOR ROL32(w_n, 23) )
///   w_{n+1} = L(w_n, σ_n) + ( R(y_n) XOR ROL32(z_n, 31) )
///
/// Parameter drift fires when (counter & (DRIFT_INTERVAL - 1)) == 0.
///
/// Exactly matches Python EAHCMState.step().
inline constexpr void
step(State& s) noexcept {
    // ---- Capture current state (all reads before any writes) ----
    const std::uint32_t x = s.x;
    const std::uint32_t y = s.y;
    const std::uint32_t z = s.z;
    const std::uint32_t w = s.w;

    // ---- Epsilon: counter-based perturbation (Flaw 5 fix) ----
    const std::uint32_t eps = rol32(s.counter, ROT_CTR_EPS) ^ EPSILON_CONST;
    s.counter = s.counter + 1u; // wraps naturally at 2^32

    // ---- Compute next state (four equations from §4.1) ----
    s.x = L(x, s.alpha) + (F(z) ^ rol32(y, ROT_Y_IN_X)) + eps;
    s.y = L(y, s.gamma) + (R(w) ^ rol32(x, ROT_X_IN_Y));
    s.z = L(z, s.mu)    + (F(x) ^ rol32(w, ROT_W_IN_Z));
    s.w = L(w, s.sigma)  + (R(y) ^ rol32(z, ROT_Z_IN_W));

    // ---- Parameter drift (§5.3) ----
    // Fires when lower bits of counter are all zero, i.e. every
    // DRIFT_INTERVAL steps. Check AFTER incrementing counter.
    if ((s.counter & (DRIFT_INTERVAL - 1u)) == 0u) {
        drift_parameters(s, x, y, z, w);
    }
}

/// Extract a 64-bit keystream word from the current state.
///
/// Formula (§6.2 of Part 2):
///   out_hi = (x + z) XOR ROL32(y, 16)
///   out_lo = (y + w) XOR ROL32(x, 16)
///   output = (out_hi << 32) | out_lo
///
/// Why not expose the raw state:
///   Direct output of x/y/z/w would allow state-recovery attacks.
///   The addition+XOR mix from two different algebraic groups makes
///   linearisation infeasible. 64 bits are extracted while 64 bits
///   remain hidden per step.
///
/// Exactly matches Python EAHCMState.extract().
[[nodiscard]] inline constexpr std::uint64_t
extract(const State& s) noexcept {
    const std::uint32_t out_hi = (s.x + s.z) ^ rol32(s.y, ROT_EXTRACT);
    const std::uint32_t out_lo = (s.y + s.w) ^ rol32(s.x, ROT_EXTRACT);
    return (static_cast<std::uint64_t>(out_hi) << 32) | static_cast<std::uint64_t>(out_lo);
}

/// Run the mandatory warmup phase.
///
/// Performs WARMUP_STEPS (256) iterations with output discarded.
/// This ensures the state is well-mixed before keystream extraction.
inline constexpr void
warmup(State& s) noexcept {
    for (std::uint32_t i = 0; i < WARMUP_STEPS; ++i) {
        step(s);
    }
}

} // namespace eahcm

#endif // EAHCM_STATE_HPP
