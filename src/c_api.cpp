// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// c_api.cpp — Implementation of the stable C ABI layer.
//
// All C++ exceptions are strictly caught and translated to C error codes here.
// C++ types (std::span, std::vector, etc.) are only constructed inside this file.
// The public header remains pure C.

#include "eahcm/eahcm.h"
#include "eahcm/aead.hpp"
#include "eahcm/cipher.hpp"
#include "eahcm/exceptions.hpp"

#include <exception>
#include <new>

// =========================================================================
// Opaque Struct Definitions
// =========================================================================

struct eahcm_aead_ctx {
    eahcm::AeadCipher inner;

    template<typename... Args>
    explicit eahcm_aead_ctx(Args&&... args) : inner(std::forward<Args>(args)...) {}
};

struct eahcm_cipher_ctx {
    eahcm::Cipher inner;

    template<typename... Args>
    explicit eahcm_cipher_ctx(Args&&... args) : inner(std::forward<Args>(args)...) {}
};

// =========================================================================
// Exception Translation Helper
// =========================================================================

// Translates the currently active exception into a stable eahcm_error_t.
// Must be called from inside a catch(...) block.
static eahcm_error_t translate_exception() noexcept {
    try {
        throw;
    } catch (const eahcm::KeyError&) {
        return EAHCM_ERROR_KEY;
    } catch (const eahcm::AuthenticationError&) {
        return EAHCM_ERROR_AUTHENTICATION;
    } catch (const eahcm::CryptoError&) {
        return EAHCM_ERROR_CRYPTO;
    } catch (const eahcm::SerializationError&) {
        return EAHCM_ERROR_SERIALIZATION;
    } catch (const eahcm::StateError&) {
        return EAHCM_ERROR_STATE;
    } catch (const std::bad_alloc&) {
        return EAHCM_ERROR_ALLOCATION;
    } catch (...) {
        return EAHCM_ERROR_INTERNAL;
    }
}

// Helper macros for robust input validation
#define VALIDATE_PTR(ptr) \
    do { if (!(ptr)) return EAHCM_ERROR_INVALID_ARGUMENT; } while(0)

#define VALIDATE_OPTIONAL_PTR(ptr, len) \
    do { if ((len) > 0 && !(ptr)) return EAHCM_ERROR_INVALID_ARGUMENT; } while(0)

#define VALIDATE_NONCE12(ptr) \
    do { if (!(ptr)) return EAHCM_ERROR_INVALID_ARGUMENT; } while(0)

extern "C" {

// =========================================================================
// Versioning
// =========================================================================

uint32_t eahcm_api_version(void) {
    return ((uint32_t)EAHCM_API_VERSION_MAJOR << 16) |
           ((uint32_t)EAHCM_API_VERSION_MINOR << 8) |
           ((uint32_t)EAHCM_API_VERSION_PATCH);
}

// =========================================================================
// Stateless AEAD (ChaCha20-Poly1305)
// =========================================================================

eahcm_error_t eahcm_aead_encrypt(
    const uint8_t* user_key, size_t user_key_len,
    const uint8_t* enonce, size_t enonce_len,
    const uint8_t* cnonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    uint8_t* tag)
{
    VALIDATE_PTR(user_key);
    VALIDATE_OPTIONAL_PTR(enonce, enonce_len);
    VALIDATE_NONCE12(cnonce);
    VALIDATE_OPTIONAL_PTR(aad, aad_len);
    VALIDATE_OPTIONAL_PTR(plaintext, pt_len);
    VALIDATE_OPTIONAL_PTR(ciphertext, pt_len);
    VALIDATE_PTR(tag);

    try {
        auto result = eahcm::aead_encrypt(
            std::span<const uint8_t>{user_key, user_key_len},
            std::span<const uint8_t>{enonce, enonce_len},
            std::span<const uint8_t>{cnonce, eahcm::AEAD_NONCE_SIZE},
            std::span<const uint8_t>{aad, aad_len},
            std::span<const uint8_t>{plaintext, pt_len}
        );

        if (pt_len > 0) {
            std::copy(result.ciphertext.begin(), result.ciphertext.end(), ciphertext);
        }
        std::copy(result.tag.begin(), result.tag.end(), tag);
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

eahcm_error_t eahcm_aead_decrypt(
    const uint8_t* user_key, size_t user_key_len,
    const uint8_t* enonce, size_t enonce_len,
    const uint8_t* cnonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* tag,
    uint8_t* plaintext)
{
    VALIDATE_PTR(user_key);
    VALIDATE_OPTIONAL_PTR(enonce, enonce_len);
    VALIDATE_NONCE12(cnonce);
    VALIDATE_OPTIONAL_PTR(aad, aad_len);
    VALIDATE_OPTIONAL_PTR(ciphertext, ct_len);
    VALIDATE_PTR(tag);
    VALIDATE_OPTIONAL_PTR(plaintext, ct_len);

    try {
        auto result = eahcm::aead_decrypt(
            std::span<const uint8_t>{user_key, user_key_len},
            std::span<const uint8_t>{enonce, enonce_len},
            std::span<const uint8_t>{cnonce, eahcm::AEAD_NONCE_SIZE},
            std::span<const uint8_t>{aad, aad_len},
            std::span<const uint8_t>{ciphertext, ct_len},
            std::span<const uint8_t>{tag, eahcm::AEAD_TAG_SIZE}
        );

        if (ct_len > 0) {
            std::copy(result.begin(), result.end(), plaintext);
        }
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

// =========================================================================
// Stateful AEAD
// =========================================================================

eahcm_error_t eahcm_aead_create(
    eahcm_aead_ctx** out_ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* info, size_t info_len)
{
    VALIDATE_PTR(out_ctx);
    VALIDATE_PTR(key);
    VALIDATE_OPTIONAL_PTR(nonce, nonce_len);
    VALIDATE_OPTIONAL_PTR(info, info_len);

    *out_ctx = nullptr;
    try {
        *out_ctx = new eahcm_aead_ctx(
            std::span<const uint8_t>{key, key_len},
            std::span<const uint8_t>{nonce, nonce_len},
            std::span<const uint8_t>{info, info_len}
        );
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

void eahcm_aead_destroy(eahcm_aead_ctx* ctx) {
    if (ctx) {
        // C++ destructor takes care of secure zeroisation
        delete ctx;
    }
}

eahcm_error_t eahcm_aead_encrypt_message(
    eahcm_aead_ctx* ctx,
    const uint8_t* cnonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    uint8_t* tag)
{
    VALIDATE_PTR(ctx);
    VALIDATE_NONCE12(cnonce);
    VALIDATE_OPTIONAL_PTR(aad, aad_len);
    VALIDATE_OPTIONAL_PTR(plaintext, pt_len);
    VALIDATE_OPTIONAL_PTR(ciphertext, pt_len);
    VALIDATE_PTR(tag);

    try {
        auto result = ctx->inner.encrypt(
            std::span<const uint8_t>{cnonce, eahcm::AEAD_NONCE_SIZE},
            std::span<const uint8_t>{aad, aad_len},
            std::span<const uint8_t>{plaintext, pt_len}
        );

        if (pt_len > 0) {
            std::copy(result.ciphertext.begin(), result.ciphertext.end(), ciphertext);
        }
        std::copy(result.tag.begin(), result.tag.end(), tag);
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

eahcm_error_t eahcm_aead_decrypt_message(
    eahcm_aead_ctx* ctx,
    const uint8_t* cnonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* tag,
    uint8_t* plaintext)
{
    VALIDATE_PTR(ctx);
    VALIDATE_NONCE12(cnonce);
    VALIDATE_OPTIONAL_PTR(aad, aad_len);
    VALIDATE_OPTIONAL_PTR(ciphertext, ct_len);
    VALIDATE_PTR(tag);
    VALIDATE_OPTIONAL_PTR(plaintext, ct_len);

    try {
        auto result = ctx->inner.decrypt(
            std::span<const uint8_t>{cnonce, eahcm::AEAD_NONCE_SIZE},
            std::span<const uint8_t>{aad, aad_len},
            std::span<const uint8_t>{ciphertext, ct_len},
            std::span<const uint8_t>{tag, eahcm::AEAD_TAG_SIZE}
        );

        if (ct_len > 0) {
            std::copy(result.begin(), result.end(), plaintext);
        }
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

eahcm_error_t eahcm_aead_reset(eahcm_aead_ctx* ctx) {
    VALIDATE_PTR(ctx);
    try {
        ctx->inner.reset();
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

// =========================================================================
// Container Format
// =========================================================================

size_t eahcm_aead_sealed_size(size_t pt_len) {
    return eahcm::CONTAINER_MIN_SIZE + pt_len;
}

eahcm_error_t eahcm_aead_seal(
    eahcm_aead_ctx* ctx,
    const uint8_t* cnonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* sealed_out, size_t sealed_capacity,
    size_t* sealed_len)
{
    VALIDATE_PTR(ctx);
    VALIDATE_NONCE12(cnonce);
    VALIDATE_OPTIONAL_PTR(aad, aad_len);
    VALIDATE_OPTIONAL_PTR(plaintext, pt_len);
    VALIDATE_PTR(sealed_out);
    VALIDATE_PTR(sealed_len);

    const size_t req_size = eahcm_aead_sealed_size(pt_len);
    if (sealed_capacity < req_size) {
        return EAHCM_ERROR_BUFFER_TOO_SMALL;
    }

    try {
        auto result = ctx->inner.seal(
            std::span<const uint8_t>{cnonce, eahcm::AEAD_NONCE_SIZE},
            std::span<const uint8_t>{aad, aad_len},
            std::span<const uint8_t>{plaintext, pt_len}
        );

        std::copy(result.begin(), result.end(), sealed_out);
        *sealed_len = result.size();
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

eahcm_error_t eahcm_aead_open(
    eahcm_aead_ctx* ctx,
    const uint8_t* sealed_in, size_t sealed_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* plaintext_out, size_t pt_capacity,
    size_t* pt_len)
{
    VALIDATE_PTR(ctx);
    VALIDATE_PTR(sealed_in);
    VALIDATE_OPTIONAL_PTR(aad, aad_len);
    VALIDATE_PTR(pt_len);

    if (sealed_len < eahcm::CONTAINER_MIN_SIZE) {
        return EAHCM_ERROR_SERIALIZATION;
    }

    const size_t expected_pt_len = sealed_len - eahcm::CONTAINER_MIN_SIZE;
    if (pt_capacity < expected_pt_len) {
        return EAHCM_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Explicit null check for output buffer if required size > 0
    if (expected_pt_len > 0 && !plaintext_out) {
        return EAHCM_ERROR_INVALID_ARGUMENT;
    }

    try {
        auto result = ctx->inner.open(
            std::span<const uint8_t>{sealed_in, sealed_len},
            std::span<const uint8_t>{aad, aad_len}
        );

        if (result.size() > 0) {
            std::copy(result.begin(), result.end(), plaintext_out);
        }
        *pt_len = result.size();
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

// =========================================================================
// Raw Keystream Cipher (Stage 1 Core)
// =========================================================================

eahcm_error_t eahcm_cipher_create(
    eahcm_cipher_ctx** out_ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* info, size_t info_len)
{
    VALIDATE_PTR(out_ctx);
    VALIDATE_PTR(key);
    VALIDATE_OPTIONAL_PTR(nonce, nonce_len);
    VALIDATE_OPTIONAL_PTR(info, info_len);

    *out_ctx = nullptr;
    try {
        *out_ctx = new eahcm_cipher_ctx(
            std::span<const uint8_t>{key, key_len},
            std::span<const uint8_t>{nonce, nonce_len},
            std::span<const uint8_t>{info, info_len}
        );
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

void eahcm_cipher_destroy(eahcm_cipher_ctx* ctx) {
    if (ctx) {
        delete ctx;
    }
}

eahcm_error_t eahcm_cipher_generate(
    eahcm_cipher_ctx* ctx,
    uint8_t* out, size_t count)
{
    VALIDATE_PTR(ctx);
    VALIDATE_OPTIONAL_PTR(out, count);

    try {
        if (count > 0) {
            ctx->inner.generate(std::span<uint8_t>{out, count});
        }
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

eahcm_error_t eahcm_cipher_reset(eahcm_cipher_ctx* ctx) {
    VALIDATE_PTR(ctx);
    try {
        ctx->inner.reset();
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

eahcm_error_t eahcm_cipher_reseed(
    eahcm_cipher_ctx* ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* info, size_t info_len)
{
    VALIDATE_PTR(ctx);
    VALIDATE_PTR(key);
    VALIDATE_OPTIONAL_PTR(nonce, nonce_len);
    VALIDATE_OPTIONAL_PTR(info, info_len);

    try {
        ctx->inner.reseed(
            std::span<const uint8_t>{key, key_len},
            std::span<const uint8_t>{nonce, nonce_len},
            std::span<const uint8_t>{info, info_len}
        );
        return EAHCM_SUCCESS;
    } catch (...) {
        return translate_exception();
    }
}

} // extern "C"
