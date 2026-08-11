// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// key_schedule.hpp — HKDF-SHA3-256 key derivation for the EAHCM cipher.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │  PUBLIC API HEADER — safe to include from user code                 │
// └─────────────────────────────────────────────────────────────────────┘
//
// Implements the full initialization pipeline:
//   USER KEY → HKDF-SHA3-256 → state + params → absorbing guard → warmup
//
// Matches the Python key_schedule.py exactly.
//
// Architecture overview
// ─────────────────────
//   Public functions (this header):
//     derive_state()            — Standard key → State pipeline
//     derive_state_with_mixing()— Authenticated-encryption variant
//     get_init_params()         — Pre-warmup introspection (for tests)
//
//   Internal HKDF helpers (NOT in this header):
//     eahcm::detail::sha3_256_hmac / hkdf_extract / hkdf_expand / hkdf
//     Declared in: include/eahcm/detail/key_schedule_impl.hpp
//     Implemented in: src/key_schedule.cpp
//
// Dependency: OpenSSL (HMAC-SHA3-256 via EVP_sha3_256).

#ifndef EAHCM_KEY_SCHEDULE_HPP
#define EAHCM_KEY_SCHEDULE_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"
#include "eahcm/exceptions.hpp"
#include "eahcm/state.hpp"
#include "eahcm/types.hpp"

namespace eahcm {

// =========================================================================
// Public key-derivation API
// =========================================================================

/// Derive a fully initialized, warmed-up EAHCM state from key material.
///
/// Pipeline (§7.1 of the specification):
///   1. Build salt = nonce ∥ optional_salt
///   2. HKDF-SHA3-256(key, salt, info+"-state-init") → 16 bytes → x, y, z, w
///   3. HKDF-SHA3-256(key, salt, info+"-param-init") → 16 bytes → α, γ, μ, σ
///   4. Clamp parameters into the chaotic regime [PARAM_FLOOR, PARAM_CEILING)
///   5. Guard absorbing states (0x00000000, 0xFFFFFFFF)
///   6. Run 256-step warmup (WARMUP_STEPS)
///
/// Exactly matches Python key_schedule.derive_state().
///
/// @note Parameters are clamped twice — once inside get_init_params() and
///       once inside make_state() — to reproduce the Python reference
///       implementation bit-for-bit.  Because PARAM_FLOOR is not a multiple
///       of DRIFT_MASK, double-clamping is NOT idempotent and produces a
///       different value than single-clamping.  This is intentional.
///
/// @param user_key  Raw user secret key (any length, must be non-empty).
/// @param nonce     Unique per-message value (12 bytes recommended).
/// @param salt      Optional additional entropy (empty span if not used).
/// @param info      Domain-separation context (default: "EAHCM-v1").
/// @return          Fully initialized, warmed-up State ready for extraction.
/// @throws KeyError if user_key is empty.
EAHCM_API [[nodiscard]] State
derive_state(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> nonce,
             std::span<const std::uint8_t> salt = {},
             std::span<const std::uint8_t> info = {});

/// Derive state with plaintext hash mixing for authenticated encryption.
///
/// After standard initialization (256-step warmup):
///   1. XOR first 16 bytes of plaintext_hash into state (little-endian)
///   2. Guard absorbing states again
///   3. Run POST_HASH_STEPS (64) additional warmup steps
///
/// This variant binds the keystream to the plaintext, providing
/// authenticated-encryption semantics when combined with a MAC.
///
/// @param user_key        Raw user secret key.
/// @param nonce           Unique per-message value.
/// @param plaintext_hash  SHA3-256(plaintext) or equivalent (≥ 16 bytes).
/// @param salt            Optional additional entropy.
/// @param info            Domain-separation context.
/// @return                Fully initialized state with hash mixing applied.
/// @throws KeyError       if user_key is empty or plaintext_hash < 16 bytes.
EAHCM_API [[nodiscard]] State
derive_state_with_mixing(std::span<const std::uint8_t> user_key,
                         std::span<const std::uint8_t> nonce,
                         std::span<const std::uint8_t> plaintext_hash,
                         std::span<const std::uint8_t> salt = {},
                         std::span<const std::uint8_t> info = {});

// =========================================================================
// Testing / introspection API
// =========================================================================

/// Pre-warmup initialization parameters (for testing and introspection).
///
/// Holds the raw state and parameter values produced by the HKDF derivation
/// step, before the warmup phase is applied.  Used by the key-schedule test
/// suite to validate intermediate values against init_vectors.json.
struct InitParams {
    std::uint32_t init_x{};
    std::uint32_t init_y{};
    std::uint32_t init_z{};
    std::uint32_t init_w{};
    std::uint32_t init_alpha{};
    std::uint32_t init_gamma{};
    std::uint32_t init_mu{};
    std::uint32_t init_sigma{};
};

/// Get the pre-warmup initialization parameters (for testing).
///
/// Performs the HKDF derivation and parameter clamping steps but stops
/// before running the warmup phase.  Useful for validating intermediate
/// values in the key-derivation pipeline against reference vectors.
///
/// @param user_key  Raw user secret key (must be non-empty).
/// @param nonce     Unique per-message value.
/// @param salt      Optional additional entropy.
/// @param info      Domain-separation context.
/// @return          Pre-warmup InitParams struct.
/// @throws KeyError if user_key is empty.
EAHCM_API [[nodiscard]] InitParams
get_init_params(std::span<const std::uint8_t> user_key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> salt = {},
                std::span<const std::uint8_t> info = {});

} // namespace eahcm

#endif // EAHCM_KEY_SCHEDULE_HPP
