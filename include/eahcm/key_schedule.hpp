// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// key_schedule.hpp — HKDF-SHA3-256 key derivation for the EAHCM cipher.
//
// Implements the full initialization pipeline:
//   USER KEY → HKDF-SHA3-256 → state + params → absorbing guard → warmup
//
// Matches the Python key_schedule.py exactly.

#ifndef EAHCM_KEY_SCHEDULE_HPP
#define EAHCM_KEY_SCHEDULE_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>
#include <stdexcept>

#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"
#include "eahcm/types.hpp"
#include "eahcm/state.hpp"
#include "eahcm/exceptions.hpp"

namespace eahcm {

// Forward declaration — implementation in key_schedule.cpp
namespace detail {

/// HMAC-SHA3-256(key, data).
/// Returns a 32-byte digest.
EAHCM_API std::array<std::uint8_t, 32>
sha3_256_hmac(std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> data);

/// HKDF-Extract (RFC 5869 §2.2) using SHA3-256.
///
/// If salt is empty, replaced by 32 zero bytes.
EAHCM_API std::array<std::uint8_t, 32>
hkdf_extract(std::span<const std::uint8_t> salt,
             std::span<const std::uint8_t> ikm);

/// HKDF-Expand (RFC 5869 §2.3) using SHA3-256.
EAHCM_API std::vector<std::uint8_t>
hkdf_expand(std::span<const std::uint8_t> prk,
            std::span<const std::uint8_t> info,
            std::size_t length);

/// Full HKDF (extract + expand) with SHA3-256.
EAHCM_API std::vector<std::uint8_t>
hkdf(std::span<const std::uint8_t> ikm,
     std::span<const std::uint8_t> salt,
     std::span<const std::uint8_t> info,
     std::size_t length);

} // namespace detail


/// Derive a fully initialized, warmed-up EAHCM state from key material.
///
/// Pipeline:
///   1. Build salt = nonce + optional_salt
///   2. HKDF-SHA3-256(key, salt, info+"-state-init") → 16 bytes → x, y, z, w
///   3. HKDF-SHA3-256(key, salt, info+"-param-init") → 16 bytes → α, γ, μ, σ
///   4. Clamp parameters into chaotic regime
///   5. Guard absorbing states (0, 0xFFFFFFFF)
///   6. Run 256-step warmup
///
/// Exactly matches Python key_schedule.derive_state().
///
/// @param user_key  Raw user secret key (any length, must be non-empty).
/// @param nonce     Unique per-message value.
/// @param salt      Optional additional entropy (empty span if not used).
/// @param info      Domain-separation context (default: "EAHCM-v1").
/// @return          Fully initialized, warmed-up state.
/// @throws KeyError if user_key is empty.
EAHCM_API [[nodiscard]] State
derive_state(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> nonce,
             std::span<const std::uint8_t> salt = {},
             std::span<const std::uint8_t> info = {});

/// Derive state with plaintext hash mixing for authenticated encryption.
///
/// After standard initialization (256-step warmup):
///   1. XOR first 16 bytes of plaintext_hash into state
///   2. Guard absorbing states again
///   3. Run 64 additional warmup steps
///
/// @param user_key        Raw user secret key.
/// @param nonce           Unique per-message value.
/// @param plaintext_hash  SHA3-256(plaintext) or equivalent (>= 16 bytes).
/// @param salt            Optional additional entropy.
/// @param info            Domain-separation context.
/// @return                Fully initialized state with hash mixing.
/// @throws KeyError       if user_key is empty or plaintext_hash < 16 bytes.
EAHCM_API [[nodiscard]] State
derive_state_with_mixing(std::span<const std::uint8_t> user_key,
                         std::span<const std::uint8_t> nonce,
                         std::span<const std::uint8_t> plaintext_hash,
                         std::span<const std::uint8_t> salt = {},
                         std::span<const std::uint8_t> info = {});

/// Results of the pre-warmup derivation (for testing/introspection).
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
EAHCM_API [[nodiscard]] InitParams
get_init_params(std::span<const std::uint8_t> user_key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> salt = {},
                std::span<const std::uint8_t> info = {});

} // namespace eahcm

#endif // EAHCM_KEY_SCHEDULE_HPP
