/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 EAHCM Authors */

/**
 * eahcm.h — Stable C ABI / Cross-Language FFI Layer for EAHCM.
 *
 * This header exposes the EAHCM 4D chaotic cryptographic engine and its
 * ChaCha20-Poly1305 AEAD construction to C and FFI-capable languages.
 *
 * It is a thin, stable ABI over the C++ implementation.
 * It is guaranteed to compile as C (C99) and C++.
 */

#ifndef EAHCM_C_API_H
#define EAHCM_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* ABI Versioning                                                            */
/* ========================================================================= */

#define EAHCM_API_VERSION_MAJOR 1
#define EAHCM_API_VERSION_MINOR 0
#define EAHCM_API_VERSION_PATCH 0

/**
 * Returns the ABI version encoded as (MAJOR << 16) | (MINOR << 8) | PATCH.
 */
uint32_t eahcm_api_version(void);

/* ========================================================================= */
/* Symbol Visibility Macro                                                   */
/* ========================================================================= */

#if defined(_WIN32) || defined(__CYGWIN__)
    #ifdef EAHCM_BUILD_SHARED
        #ifdef EAHCM_EXPORTS
            #define EAHCM_C_API __declspec(dllexport)
        #else
            #define EAHCM_C_API __declspec(dllimport)
        #endif
    #else
        #define EAHCM_C_API
    #endif
#else
    #if defined(__GNUC__) || defined(__clang__)
        #define EAHCM_C_API __attribute__((visibility("default")))
    #else
        #define EAHCM_C_API
    #endif
#endif

/* ========================================================================= */
/* Error Codes                                                               */
/* ========================================================================= */

/**
 * Stable error codes returned by all C API functions.
 * No C++ exceptions cross the ABI boundary; they are caught and mapped here.
 */
typedef int eahcm_error_t;

#define EAHCM_SUCCESS                  0
#define EAHCM_ERROR_INVALID_ARGUMENT (-1)  /* NULL pointer or bad length */
#define EAHCM_ERROR_KEY              (-2)  /* Invalid key/nonce material */
#define EAHCM_ERROR_AUTHENTICATION   (-3)  /* Poly1305 tag mismatch */
#define EAHCM_ERROR_CRYPTO           (-4)  /* Backend/OpenSSL failure */
#define EAHCM_ERROR_SERIALIZATION    (-5)  /* Malformed container/state */
#define EAHCM_ERROR_STATE            (-6)  /* Invalid cipher state */
#define EAHCM_ERROR_ALLOCATION       (-7)  /* Memory allocation failure (new) */
#define EAHCM_ERROR_BUFFER_TOO_SMALL (-8)  /* Output buffer insufficient */
#define EAHCM_ERROR_INTERNAL         (-99) /* Unexpected std::exception or ... */

/* ========================================================================= */
/* Opaque Contexts                                                           */
/* ========================================================================= */

/**
 * Opaque handle to the stateful AEAD cipher (ChaCha20-Poly1305).
 * Represents an instance of eahcm::AeadCipher.
 */
typedef struct eahcm_aead_ctx eahcm_aead_ctx;

/**
 * Opaque handle to the raw keystream cipher.
 * Represents an instance of eahcm::Cipher.
 */
typedef struct eahcm_cipher_ctx eahcm_cipher_ctx;

/* ========================================================================= */
/* Stateless AEAD (ChaCha20-Poly1305)                                        */
/* ========================================================================= */

/**
 * One-shot AEAD encryption.
 *
 * @param user_key      Raw secret key (must not be NULL, length > 0).
 * @param user_key_len  Length of user_key in bytes.
 * @param enonce        EAHCM initialization nonce (can be NULL if enonce_len == 0).
 * @param enonce_len    Length of EAHCM nonce in bytes.
 * @param cnonce        ChaCha20 nonce (exactly 12 bytes).
 * @param aad           Additional authenticated data (can be NULL if aad_len == 0).
 * @param aad_len       Length of AAD in bytes.
 * @param plaintext     Message to encrypt (can be NULL if pt_len == 0).
 * @param pt_len        Length of plaintext in bytes.
 * @param ciphertext    Output buffer (capacity must be >= pt_len).
 * @param tag           Output buffer for the 16-byte Poly1305 tag.
 * @return              EAHCM_SUCCESS or an error code.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_encrypt(
    const uint8_t* user_key, size_t user_key_len,
    const uint8_t* enonce, size_t enonce_len,
    const uint8_t* cnonce, /* always 12 bytes */
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    uint8_t* tag /* always 16 bytes */
);

/**
 * One-shot AEAD decryption.
 *
 * @param user_key      Raw secret key (must not be NULL, length > 0).
 * @param user_key_len  Length of user_key in bytes.
 * @param enonce        EAHCM initialization nonce (can be NULL if enonce_len == 0).
 * @param enonce_len    Length of EAHCM nonce in bytes.
 * @param cnonce        ChaCha20 nonce (exactly 12 bytes).
 * @param aad           Additional authenticated data (can be NULL if aad_len == 0).
 * @param aad_len       Length of AAD in bytes.
 * @param ciphertext    Encrypted message (can be NULL if ct_len == 0).
 * @param ct_len        Length of ciphertext in bytes.
 * @param tag           16-byte Poly1305 tag from encryption.
 * @param plaintext     Output buffer (capacity must be >= ct_len).
 * @return              EAHCM_SUCCESS, EAHCM_ERROR_AUTHENTICATION, or other error.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_decrypt(
    const uint8_t* user_key, size_t user_key_len,
    const uint8_t* enonce, size_t enonce_len,
    const uint8_t* cnonce, /* always 12 bytes */
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* tag, /* always 16 bytes */
    uint8_t* plaintext
);

/* ========================================================================= */
/* Stateful AEAD (ChaCha20-Poly1305)                                         */
/* ========================================================================= */

/**
 * Create a stateful AEAD context.
 *
 * @param out_ctx   Pointer to receive the newly allocated context handle.
 * @param key       Raw secret key.
 * @param key_len   Length of key.
 * @param nonce     EAHCM initialization nonce.
 * @param nonce_len Length of nonce.
 * @param info      Optional domain separation info (NULL if info_len == 0).
 * @param info_len  Length of info.
 * @return          EAHCM_SUCCESS on success, allocates memory for out_ctx.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_create(
    eahcm_aead_ctx** out_ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* info, size_t info_len
);

/**
 * Destroy a stateful AEAD context.
 * Securely wipes internal state before freeing memory.
 *
 * @param ctx  Handle to destroy (if NULL, a no-op).
 */
EAHCM_C_API void eahcm_aead_destroy(eahcm_aead_ctx* ctx);

/**
 * Encrypt a message using a stateful AEAD context.
 * Advances the EAHCM state, providing a fresh ChaCha20 key.
 *
 * @param ctx           Valid AEAD context handle.
 * @param cnonce        ChaCha20 nonce (exactly 12 bytes).
 * @param aad           Additional authenticated data.
 * @param aad_len       Length of AAD.
 * @param plaintext     Message to encrypt.
 * @param pt_len        Length of plaintext.
 * @param ciphertext    Output buffer (must have capacity >= pt_len).
 * @param tag           Output buffer for 16-byte tag.
 * @return              EAHCM_SUCCESS or error code.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_encrypt_message(
    eahcm_aead_ctx* ctx,
    const uint8_t* cnonce, /* 12 bytes */
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    uint8_t* tag /* 16 bytes */
);

/**
 * Decrypt a message using a stateful AEAD context.
 * Performs verify-before-use authentication.
 *
 * @param ctx           Valid AEAD context handle.
 * @param cnonce        ChaCha20 nonce (exactly 12 bytes).
 * @param aad           Additional authenticated data.
 * @param aad_len       Length of AAD.
 * @param ciphertext    Message to decrypt.
 * @param ct_len        Length of ciphertext.
 * @param tag           16-byte tag to verify against.
 * @param plaintext     Output buffer (must have capacity >= ct_len).
 * @return              EAHCM_SUCCESS on authentication success and decryption.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_decrypt_message(
    eahcm_aead_ctx* ctx,
    const uint8_t* cnonce, /* 12 bytes */
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* tag, /* 16 bytes */
    uint8_t* plaintext
);

/**
 * Reset the AEAD context to its initial derived state.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_reset(eahcm_aead_ctx* ctx);

/* ========================================================================= */
/* Container Format (Seal / Open)                                            */
/* ========================================================================= */

/**
 * Get the exact byte size required for a sealed container blob.
 *
 * @param pt_len  Length of the plaintext.
 * @return        Required buffer size for eahcm_aead_seal.
 */
EAHCM_C_API size_t eahcm_aead_sealed_size(size_t pt_len);

/**
 * Encrypt and seal into the EAHCM binary container format.
 *
 * @param ctx             Valid AEAD context handle.
 * @param cnonce          ChaCha20 nonce (12 bytes).
 * @param aad             Additional authenticated data (not embedded in blob).
 * @param aad_len         Length of AAD.
 * @param plaintext       Message to seal.
 * @param pt_len          Length of plaintext.
 * @param sealed_out      Output buffer for the sealed blob.
 * @param sealed_capacity Capacity of sealed_out (must be >= eahcm_aead_sealed_size(pt_len)).
 * @param sealed_len      [out] Exact size written to sealed_out.
 * @return                EAHCM_SUCCESS or error code.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_seal(
    eahcm_aead_ctx* ctx,
    const uint8_t* cnonce, /* 12 bytes */
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* sealed_out, size_t sealed_capacity,
    size_t* sealed_len
);

/**
 * Open and decrypt an EAHCM binary container format.
 *
 * @param ctx               Valid AEAD context handle.
 * @param sealed_in         The sealed blob.
 * @param sealed_len        Length of sealed_in.
 * @param aad               Additional authenticated data.
 * @param aad_len           Length of AAD.
 * @param plaintext_out     Output buffer for plaintext.
 * @param pt_capacity       Capacity of plaintext_out (sealed_len minus overhead).
 * @param pt_len            [out] Exact size written to plaintext_out.
 * @return                  EAHCM_SUCCESS on authentication and decryption success.
 */
EAHCM_C_API eahcm_error_t eahcm_aead_open(
    eahcm_aead_ctx* ctx,
    const uint8_t* sealed_in, size_t sealed_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* plaintext_out, size_t pt_capacity,
    size_t* pt_len
);

/* ========================================================================= */
/* Raw Keystream Cipher (Stage 1 Core)                                       */
/* ========================================================================= */

/**
 * Create a raw keystream cipher context.
 */
EAHCM_C_API eahcm_error_t eahcm_cipher_create(
    eahcm_cipher_ctx** out_ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* info, size_t info_len
);

/**
 * Destroy a raw keystream cipher context.
 */
EAHCM_C_API void eahcm_cipher_destroy(eahcm_cipher_ctx* ctx);

/**
 * Generate keystream bytes.
 *
 * @param ctx      Valid cipher context handle.
 * @param out      Buffer to receive keystream.
 * @param count    Number of bytes to generate.
 */
EAHCM_C_API eahcm_error_t eahcm_cipher_generate(
    eahcm_cipher_ctx* ctx,
    uint8_t* out, size_t count
);

/**
 * Reset the raw keystream cipher context to its initial derived state.
 */
EAHCM_C_API eahcm_error_t eahcm_cipher_reset(eahcm_cipher_ctx* ctx);

/**
 * Reseed the raw keystream cipher context with new key material.
 */
EAHCM_C_API eahcm_error_t eahcm_cipher_reseed(
    eahcm_cipher_ctx* ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* info, size_t info_len
);

#ifdef __cplusplus
}
#endif

#endif /* EAHCM_C_API_H */
