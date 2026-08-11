// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// exceptions.hpp — Error types for the EAHCM library.
//
// Hierarchy:
//   std::runtime_error
//     └─ Error              — base for all EAHCM errors
//          ├─ KeyError           — invalid key/nonce material
//          ├─ SerializationError — binary/JSON codec failure
//          ├─ ValidationError    — reference-vector mismatch
//          ├─ StateError         — cipher used in invalid state
//          ├─ AuthenticationError— Poly1305 tag mismatch (Stage 2)
//          └─ CryptoError        — backend/OpenSSL failure (Stage 2)

#ifndef EAHCM_EXCEPTIONS_HPP
#define EAHCM_EXCEPTIONS_HPP

#include <stdexcept>
#include <string>

namespace eahcm {

/// Base exception for all EAHCM errors.
class Error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Thrown when key material is invalid (empty key, bad nonce length, etc.).
class KeyError : public Error {
    using Error::Error;
};

/// Thrown when serialization/deserialization fails.
class SerializationError : public Error {
    using Error::Error;
};

/// Thrown when a reference vector mismatch is detected.
class ValidationError : public Error {
    using Error::Error;
};

/// Thrown when the cipher is used in an invalid state.
class StateError : public Error {
    using Error::Error;
};

// =========================================================================
// Stage 2 exceptions
// =========================================================================

/// Thrown when ChaCha20-Poly1305 AEAD authentication fails (tag mismatch).
///
/// This exception indicates that at least one of the following has been
/// modified since encryption:
///   - the ciphertext
///   - the authentication tag
///   - the AAD
///   - the key
///   - the nonce
///
/// It is NEVER thrown for implementation errors; only for deliberate
/// authentication failure.  After catching this exception the caller MUST:
///   - Discard any partial output (none is returned by the API)
///   - Not retry decryption with the same corrupted material
///
/// Security invariant: no plaintext is ever returned when this is thrown.
class AuthenticationError : public Error {
    using Error::Error;
};

/// Thrown when an underlying cryptographic backend operation fails
/// unexpectedly.
///
/// This indicates a platform or implementation problem (e.g. an OpenSSL
/// call returned an error code for a reason other than tag mismatch),
/// not a protocol-level authentication failure.  It is intentionally
/// distinct from AuthenticationError so callers can handle them
/// separately.
///
/// Examples: EVP_CIPHER_CTX_new() returns NULL, EVP_EncryptFinal_ex()
/// returns an internal OpenSSL error.
class CryptoError : public Error {
    using Error::Error;
};

} // namespace eahcm

#endif // EAHCM_EXCEPTIONS_HPP
