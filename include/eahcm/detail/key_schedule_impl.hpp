// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// detail/key_schedule_impl.hpp — Internal HKDF helper declarations.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │  INTERNAL HEADER — NOT PART OF THE PUBLIC API                      │
// │                                                                     │
// │  Do NOT include this header from user code or from public headers.  │
// │  It is consumed exclusively by src/key_schedule.cpp.               │
// │                                                                     │
// │  Reason: the HKDF building blocks (sha3_256_hmac, hkdf_extract,    │
// │  hkdf_expand, hkdf) are implementation details of the key-schedule  │
// │  and must not form part of the installed public interface.          │
// └─────────────────────────────────────────────────────────────────────┘
//
// Architecture position:
//
//   Public layer:   include/eahcm/key_schedule.hpp
//                     └─ derive_state(), derive_state_with_mixing(),
//                        get_init_params(), InitParams
//   Internal layer: include/eahcm/detail/key_schedule_impl.hpp  ← this file
//                     └─ eahcm::detail::{sha3_256_hmac, hkdf_extract,
//                                         hkdf_expand, hkdf}
//   Implementation: src/key_schedule.cpp (includes both layers)

#ifndef EAHCM_DETAIL_KEY_SCHEDULE_IMPL_HPP
#define EAHCM_DETAIL_KEY_SCHEDULE_IMPL_HPP

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "eahcm/config.hpp"

namespace eahcm::detail {

// =========================================================================
// Low-level cryptographic primitives (RFC 5869 over HMAC-SHA3-256)
//
// These functions are tested indirectly through the key-schedule integration
// tests (test_key_schedule.cpp / init_vectors.json).
// =========================================================================

/// HMAC-SHA3-256(key, data) → 32-byte digest.
///
/// Implements the standard HMAC construction (RFC 2104) using SHA3-256 as
/// the underlying hash.  This matches Python's `hmac.new(key, data,
/// hashlib.sha3_256)` exactly.
///
/// @note OpenSSL 3.x marks the `HMAC()` convenience function deprecated in
///       favour of EVP_MAC.  The call still works correctly and produces
///       bit-identical output.  A migration to EVP_MAC is deferred to a
///       future stage that adds an OpenSSL-version compatibility shim.
///
/// @param key   The HMAC key (arbitrary length).
/// @param data  The data to authenticate.
/// @return      32-byte HMAC-SHA3-256 digest.
/// @throws std::runtime_error if the underlying OpenSSL call fails.
EAHCM_API std::array<std::uint8_t, 32>
sha3_256_hmac(std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> data);

/// HKDF-Extract (RFC 5869 §2.2) using HMAC-SHA3-256.
///
/// Converts input key material (IKM) and an optional salt into a
/// pseudorandom key (PRK).  If `salt` is empty, 32 zero bytes are used
/// as the salt per RFC 5869.
///
/// @param salt  Optional salt value (recommended, but may be empty).
/// @param ikm   Input key material.
/// @return      32-byte pseudorandom key.
EAHCM_API std::array<std::uint8_t, 32>
hkdf_extract(std::span<const std::uint8_t> salt,
             std::span<const std::uint8_t> ikm);

/// HKDF-Expand (RFC 5869 §2.3) using HMAC-SHA3-256.
///
/// Expands a pseudorandom key (PRK) and optional context information into
/// output key material (OKM) of the requested length.
///
/// @param prk     32-byte pseudorandom key from hkdf_extract().
/// @param info    Context and application-specific information (may be empty).
/// @param length  Desired output length in bytes (max: 255 × 32 = 8160).
/// @return        `length` bytes of output key material.
/// @throws std::invalid_argument if length > 8160.
EAHCM_API std::vector<std::uint8_t>
hkdf_expand(std::span<const std::uint8_t> prk,
            std::span<const std::uint8_t> info,
            std::size_t length);

/// Full HKDF (Extract + Expand) using HMAC-SHA3-256.
///
/// Convenience wrapper: hkdf(ikm, salt, info, length) ==
///   hkdf_expand(hkdf_extract(salt, ikm), info, length)
///
/// @param ikm     Input key material.
/// @param salt    Optional salt (may be empty).
/// @param info    Domain-separation / context string (may be empty).
/// @param length  Desired output length in bytes.
/// @return        `length` bytes of derived key material.
EAHCM_API std::vector<std::uint8_t>
hkdf(std::span<const std::uint8_t> ikm,
     std::span<const std::uint8_t> salt,
     std::span<const std::uint8_t> info,
     std::size_t length);

} // namespace eahcm::detail

#endif // EAHCM_DETAIL_KEY_SCHEDULE_IMPL_HPP
