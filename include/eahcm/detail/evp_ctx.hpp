// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// detail/evp_ctx.hpp — RAII wrapper for OpenSSL EVP_CIPHER_CTX.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │  INTERNAL HEADER — NOT PART OF THE PUBLIC API                       │
// │  Included only by: src/aead.cpp                                     │
// └─────────────────────────────────────────────────────────────────────┘
//
// EVP_CIPHER_CTX holds the state of an OpenSSL cipher operation and may
// contain sensitive key material internally.  EVP_CIPHER_CTX_free() calls
// EVP_CIPHER_CTX_reset() which zeroes sensitive fields before releasing the
// allocation, so our RAII wrapper automatically provides secure cleanup on
// every exit path (including exceptions).

#pragma once
#ifndef EAHCM_DETAIL_EVP_CTX_HPP
#define EAHCM_DETAIL_EVP_CTX_HPP

#include <memory>        // std::unique_ptr
#include <stdexcept>     // std::bad_alloc
#include <openssl/evp.h> // EVP_CIPHER_CTX_new / EVP_CIPHER_CTX_free

namespace eahcm::detail {

// ---- RAII deleter ----

struct EvpCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
        // EVP_CIPHER_CTX_free handles nullptr gracefully
        EVP_CIPHER_CTX_free(ctx);
    }
};

/// RAII owning pointer for EVP_CIPHER_CTX.
///
/// Calls EVP_CIPHER_CTX_free (which internally calls EVP_CIPHER_CTX_reset,
/// zeroing sensitive key material) on destruction.
using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter>;

/// Allocate a fresh EVP_CIPHER_CTX.
///
/// @throws std::bad_alloc if OpenSSL cannot allocate the context.
[[nodiscard]] inline EvpCtxPtr make_evp_ctx() {
    EvpCtxPtr ptr(EVP_CIPHER_CTX_new());
    if (!ptr) throw std::bad_alloc{};
    return ptr;
}

} // namespace eahcm::detail

#endif // EAHCM_DETAIL_EVP_CTX_HPP
