// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// key_schedule.cpp — HKDF-SHA3-256 key derivation for the EAHCM cipher.
//
// Implements the key-derivation pipeline using OpenSSL's HMAC and EVP APIs.
//
// Construction note (HMAC over SHA3-256)
// ───────────────────────────────────────
// SHA3 does not inherently need HMAC for domain separation (KMAC exists),
// but the Python reference implementation uses:
//   hmac.new(key, data, hashlib.sha3_256)
// which is the standard HMAC-SHA3-256 construction (RFC 2104).
// We must reproduce this exactly to remain bit-compatible.
//
// OpenSSL compatibility note
// ──────────────────────────
// We use the OpenSSL `HMAC()` convenience function (from <openssl/hmac.h>).
// In OpenSSL 3.0+, HMAC() is marked deprecated in favour of the EVP_MAC API.
// The function still works correctly and produces identical output.
// A future stage will introduce an OpenSSL-version compatibility shim that
// dispatches to EVP_MAC on OpenSSL ≥ 3.0 and to HMAC() on OpenSSL < 3.0.
// Until then, suppress deprecation warnings in the CMake build if needed.
//
// Key-derivation pipeline (per §7.1 of the specification)
// ─────────────────────────────────────────────────────────
//   derive_state():
//     1. derived_salt ← nonce ∥ salt
//     2. state_bytes  ← HKDF(key, derived_salt, info+"-state-init", 16)
//     3. param_bytes  ← HKDF(key, derived_salt, info+"-param-init", 16)
//     4. x,y,z,w      ← load_le32(state_bytes[0..15])
//     5. α,γ,μ,σ      ← clamp_param(load_le32(param_bytes[0..15]))
//     6. guard_absorbing() on x,y,z,w
//     7. make_state()  (clamps params a second time — see note below)
//     8. warmup(256 steps)
//
//   Double-clamping note:
//     get_init_params() clamps α,γ,μ,σ once.  derive_state() then calls
//     make_state() which clamps them again.  Because PARAM_FLOOR is not a
//     multiple of DRIFT_MASK, double-clamping is NOT idempotent.  This
//     reproduces the Python reference exactly and must not be changed.

#include "eahcm/key_schedule.hpp"
#include "eahcm/detail/key_schedule_impl.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

// OpenSSL headers for HMAC-SHA3-256
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace eahcm::detail {

// =========================================================================
// HMAC-SHA3-256 and HKDF building blocks
// =========================================================================

std::array<std::uint8_t, 32>
sha3_256_hmac(std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> result{};
    unsigned int len = 32;

    // Note: HMAC() is deprecated in OpenSSL 3.x — see file-level comment.
    unsigned char* out = HMAC(EVP_sha3_256(),
                              key.data(), static_cast<int>(key.size()),
                              data.data(), data.size(),
                              result.data(), &len);
    if (!out) {
        throw std::runtime_error("HMAC-SHA3-256 failed");
    }

    return result;
}

std::array<std::uint8_t, 32>
hkdf_extract(std::span<const std::uint8_t> salt,
             std::span<const std::uint8_t> ikm) {
    if (salt.empty()) {
        // RFC 5869 §2.2: if salt is not provided, use a string of HashLen zeros
        std::array<std::uint8_t, 32> zero_salt{};
        return sha3_256_hmac(zero_salt, ikm);
    }
    return sha3_256_hmac(salt, ikm);
}

std::vector<std::uint8_t>
hkdf_expand(std::span<const std::uint8_t> prk,
            std::span<const std::uint8_t> info,
            std::size_t length) {
    constexpr std::size_t hash_len = 32; // SHA3-256 output length
    if (length > hash_len * 255) {
        throw std::invalid_argument(
            "HKDF-Expand: requested length exceeds maximum (255 × HashLen)");
    }

    const std::size_t n_blocks = (length + hash_len - 1) / hash_len;
    std::vector<std::uint8_t> okm;
    okm.reserve(n_blocks * hash_len);

    // T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i)
    std::vector<std::uint8_t> t_prev;
    for (std::size_t i = 1; i <= n_blocks; ++i) {
        std::vector<std::uint8_t> input;
        input.reserve(t_prev.size() + info.size() + 1);
        input.insert(input.end(), t_prev.begin(), t_prev.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(static_cast<std::uint8_t>(i));

        auto block = sha3_256_hmac(prk, input);
        t_prev.assign(block.begin(), block.end());
        okm.insert(okm.end(), block.begin(), block.end());
    }

    okm.resize(length);
    return okm;
}

std::vector<std::uint8_t>
hkdf(std::span<const std::uint8_t> ikm,
     std::span<const std::uint8_t> salt,
     std::span<const std::uint8_t> info,
     std::size_t length) {
    auto prk = hkdf_extract(salt, ikm);
    return hkdf_expand(prk, info, length);
}

} // namespace eahcm::detail


namespace eahcm {

// =========================================================================
// Private helpers (file-scope only)
// =========================================================================

// Default domain-separation info string (ASCII bytes of "EAHCM-v1")
static constexpr std::uint8_t DEFAULT_INFO[] = {
    'E','A','H','C','M','-','v','1'
};

/// Build the HKDF info string: (user info or default) + suffix.
static std::vector<std::uint8_t>
build_info(std::span<const std::uint8_t> info, const char* suffix) {
    std::vector<std::uint8_t> result;
    if (info.empty()) {
        result.assign(std::begin(DEFAULT_INFO), std::end(DEFAULT_INFO));
    } else {
        result.assign(info.begin(), info.end());
    }
    const std::size_t suf_len = std::strlen(suffix);
    result.insert(result.end(),
                  reinterpret_cast<const std::uint8_t*>(suffix),
                  reinterpret_cast<const std::uint8_t*>(suffix) + suf_len);
    return result;
}

/// Build the HKDF salt: nonce ∥ optional_salt.
static std::vector<std::uint8_t>
build_salt(std::span<const std::uint8_t> nonce,
           std::span<const std::uint8_t> salt) {
    std::vector<std::uint8_t> derived;
    derived.reserve(nonce.size() + salt.size());
    derived.insert(derived.end(), nonce.begin(), nonce.end());
    derived.insert(derived.end(), salt.begin(), salt.end());
    return derived;
}

// =========================================================================
// Public API implementation
// =========================================================================

InitParams
get_init_params(std::span<const std::uint8_t> user_key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> salt,
                std::span<const std::uint8_t> info) {
    if (user_key.empty()) {
        throw KeyError("user_key must not be empty");
    }

    auto derived_salt = build_salt(nonce, salt);
    auto state_info   = build_info(info, "-state-init");
    auto param_info   = build_info(info, "-param-init");

    // Derive 16 bytes for initial state variables
    auto state_bytes = detail::hkdf(user_key, derived_salt, state_info, 16);

    // Derive 16 bytes for chaotic parameters
    auto param_bytes = detail::hkdf(user_key, derived_salt, param_info, 16);

    // Parse as little-endian uint32s (matches Python struct.unpack("<I", ...))
    auto raw_x = load_le32(state_bytes.data());
    auto raw_y = load_le32(state_bytes.data() + 4);
    auto raw_z = load_le32(state_bytes.data() + 8);
    auto raw_w = load_le32(state_bytes.data() + 12);

    // First clamp of parameters (second clamp occurs in make_state)
    auto raw_alpha = clamp_param(load_le32(param_bytes.data()));
    auto raw_gamma = clamp_param(load_le32(param_bytes.data() + 4));
    auto raw_mu    = clamp_param(load_le32(param_bytes.data() + 8));
    auto raw_sigma = clamp_param(load_le32(param_bytes.data() + 12));

    // Guard absorbing states before warmup
    auto init_x = guard_absorbing(raw_x);
    auto init_y = guard_absorbing(raw_y);
    auto init_z = guard_absorbing(raw_z);
    auto init_w = guard_absorbing(raw_w);

    return InitParams{
        init_x, init_y, init_z, init_w,
        raw_alpha, raw_gamma, raw_mu, raw_sigma
    };
}

State
derive_state(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> nonce,
             std::span<const std::uint8_t> salt,
             std::span<const std::uint8_t> info) {
    auto params = get_init_params(user_key, nonce, salt, info);

    // make_state() clamps parameters a second time (see double-clamping note
    // in the file-level comment).  This reproduces Python bit-for-bit.
    State s = make_state(
        params.init_x, params.init_y, params.init_z, params.init_w,
        params.init_alpha, params.init_gamma, params.init_mu, params.init_sigma
    );

    // Mandatory 256-step warmup — output is discarded
    warmup(s);

    return s;
}

State
derive_state_with_mixing(std::span<const std::uint8_t> user_key,
                         std::span<const std::uint8_t> nonce,
                         std::span<const std::uint8_t> plaintext_hash,
                         std::span<const std::uint8_t> salt,
                         std::span<const std::uint8_t> info) {
    if (plaintext_hash.size() < 16) {
        throw KeyError("plaintext_hash must be at least 16 bytes");
    }

    // Standard initialization (256-step warmup included)
    State s = derive_state(user_key, nonce, salt, info);

    // XOR first 16 bytes of plaintext hash into state (little-endian parse,
    // matching Python key_schedule.derive_state_with_mixing())
    const auto hx = load_le32(plaintext_hash.data());
    const auto hy = load_le32(plaintext_hash.data() + 4);
    const auto hz = load_le32(plaintext_hash.data() + 8);
    const auto hw = load_le32(plaintext_hash.data() + 12);

    s.x = guard_absorbing(s.x ^ hx);
    s.y = guard_absorbing(s.y ^ hy);
    s.z = guard_absorbing(s.z ^ hz);
    s.w = guard_absorbing(s.w ^ hw);

    // POST_HASH_STEPS (64) additional warmup steps to diffuse the hash XOR
    for (std::uint32_t i = 0; i < POST_HASH_STEPS; ++i) {
        step(s);
    }

    return s;
}

} // namespace eahcm
