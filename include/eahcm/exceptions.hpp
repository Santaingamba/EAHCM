// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// exceptions.hpp — Error types for the EAHCM library.

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

} // namespace eahcm

#endif // EAHCM_EXCEPTIONS_HPP
