// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// key_schedule.cpp — HKDF-SHA3-256 implementation for the EAHCM cipher.
//
// This implements the key derivation pipeline using the stdlib's
// <hmac> + <sha3> or a bundled implementation.
//
// We implement HMAC-SHA3-256 using the standard HMAC construction
// (RFC 2104) over SHA3-256. Note: SHA3 does not need HMAC for security
// (KMAC exists), but the Python reference uses hmac.new(key, data, sha3_256)
// which is standard HMAC construction, so we must match it exactly.

#include "eahcm/key_schedule.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

// We use OpenSSL for SHA3-256 and HMAC.
// If OpenSSL is not available, a bundled implementation could be provided.
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace eahcm::detail {


// ---- HMAC-SHA3-256 ----
std::array<std::uint8_t, 32>
sha3_256_hmac(std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> result{};
    unsigned int len = 32;

    // Use the HMAC API
    unsigned char* out = HMAC(EVP_sha3_256(),
                              key.data(), static_cast<int>(key.size()),
                              data.data(), data.size(),
                              result.data(), &len);
    if (!out) {
        throw std::runtime_error("HMAC-SHA3-256 failed");
    }

    return result;
}

// ---- HKDF-Extract (RFC 5869 §2.2) ----
std::array<std::uint8_t, 32>
hkdf_extract(std::span<const std::uint8_t> salt,
             std::span<const std::uint8_t> ikm) {
    if (salt.empty()) {
        // If salt is empty, use 32 zero bytes
        std::array<std::uint8_t, 32> zero_salt{};
        return sha3_256_hmac(zero_salt, ikm);
    }
    return sha3_256_hmac(salt, ikm);
}

// ---- HKDF-Expand (RFC 5869 §2.3) ----
std::vector<std::uint8_t>
hkdf_expand(std::span<const std::uint8_t> prk,
            std::span<const std::uint8_t> info,
            std::size_t length) {
    constexpr std::size_t hash_len = 32; // SHA3-256 output
    if (length > hash_len * 255) {
        throw std::invalid_argument(
            "HKDF-Expand: requested length exceeds maximum");
    }

    const std::size_t n_blocks = (length + hash_len - 1) / hash_len;
    std::vector<std::uint8_t> okm;
    okm.reserve(n_blocks * hash_len);

    std::vector<std::uint8_t> t_prev;
    for (std::size_t i = 1; i <= n_blocks; ++i) {
        // Build input: T(i-1) || info || i
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

// ---- Full HKDF ----
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

// Default info string
static constexpr std::uint8_t DEFAULT_INFO[] = {
    'E','A','H','C','M','-','v','1'
};

// Helper to build info+suffix
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

// Helper to build derived salt = nonce + salt
static std::vector<std::uint8_t>
build_salt(std::span<const std::uint8_t> nonce,
           std::span<const std::uint8_t> salt) {
    std::vector<std::uint8_t> derived;
    derived.reserve(nonce.size() + salt.size());
    derived.insert(derived.end(), nonce.begin(), nonce.end());
    derived.insert(derived.end(), salt.begin(), salt.end());
    return derived;
}

InitParams
get_init_params(std::span<const std::uint8_t> user_key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> salt,
                std::span<const std::uint8_t> info) {
    if (user_key.empty()) {
        throw KeyError("user_key must not be empty");
    }

    auto derived_salt = build_salt(nonce, salt);
    auto state_info = build_info(info, "-state-init");
    auto param_info = build_info(info, "-param-init");

    // Derive 16 bytes for state
    auto state_bytes = detail::hkdf(
        user_key, derived_salt, state_info, 16);

    // Derive 16 bytes for parameters
    auto param_bytes = detail::hkdf(
        user_key, derived_salt, param_info, 16);

    // Parse as little-endian uint32s (matches Python struct.unpack("<I", ...))
    auto raw_x = load_le32(state_bytes.data());
    auto raw_y = load_le32(state_bytes.data() + 4);
    auto raw_z = load_le32(state_bytes.data() + 8);
    auto raw_w = load_le32(state_bytes.data() + 12);

    auto raw_alpha = clamp_param(load_le32(param_bytes.data()));
    auto raw_gamma = clamp_param(load_le32(param_bytes.data() + 4));
    auto raw_mu    = clamp_param(load_le32(param_bytes.data() + 8));
    auto raw_sigma = clamp_param(load_le32(param_bytes.data() + 12));

    // Guard absorbing states
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

    // We must use make_state here to reproduce the exact behavior of Python's
    // EAHCMKeySchedule.initialize(). In Python, the params are clamped once in
    // _clamp_param, and then clamped AGAIN when passed into EAHCMState.__init__.
    // Because PARAM_FLOOR is not a multiple of DRIFT_MASK, clamping twice is
    // NOT idempotent and produces a different value than clamping once.
    // To match Python bit-for-bit, we must double-clamp.
    State s = make_state(
        params.init_x, params.init_y, params.init_z, params.init_w,
        params.init_alpha, params.init_gamma, params.init_mu, params.init_sigma
    );

    // Warmup: 256 steps with output discarded
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

    // Standard initialization first
    State s = derive_state(user_key, nonce, salt, info);

    // XOR hash into state (little-endian parse, matching Python)
    const auto hx = load_le32(plaintext_hash.data());
    const auto hy = load_le32(plaintext_hash.data() + 4);
    const auto hz = load_le32(plaintext_hash.data() + 8);
    const auto hw = load_le32(plaintext_hash.data() + 12);

    s.x = guard_absorbing(s.x ^ hx);
    s.y = guard_absorbing(s.y ^ hy);
    s.z = guard_absorbing(s.z ^ hz);
    s.w = guard_absorbing(s.w ^ hw);

    // 64 additional warmup steps
    for (std::uint32_t i = 0; i < POST_HASH_STEPS; ++i) {
        step(s);
    }

    return s;
}

} // namespace eahcm
