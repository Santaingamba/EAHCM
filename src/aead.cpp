// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// aead.cpp — Stage 2: ChaCha20-Poly1305 AEAD construction implementation.
//
// Construction summary (RFC 8439 + EAHCM):
//
//   ChaCha20 key source: 4 × (step + extract) from EAHCM state, LE-serialized
//   AEAD primitive:      EVP_chacha20_poly1305() — RFC 8439 compliant
//   Tag size:            16 bytes (Poly1305)
//   Nonce size:          12 bytes (96-bit, caller-provided)
//   Authentication:      AAD + padded ciphertext + lengths (standard AEAD)
//
// OpenSSL EVP sequence for ENCRYPT:
//   EVP_EncryptInit_ex(cipher=chacha20_poly1305, key=NULL, iv=NULL)
//   EVP_CIPHER_CTX_ctrl(IVLEN, 12)
//   EVP_EncryptInit_ex(cipher=NULL, key=32B, iv=12B)
//   EVP_EncryptUpdate(out=NULL, aad)            ← signals AAD
//   EVP_EncryptUpdate(out=ciphertext, plaintext)
//   EVP_EncryptFinal_ex(scratch)               ← 0 bytes for stream cipher
//   EVP_CIPHER_CTX_ctrl(GET_TAG, 16, tag_buf)
//
// OpenSSL EVP sequence for DECRYPT (verify-before-use):
//   EVP_DecryptInit_ex(cipher=chacha20_poly1305, key=NULL, iv=NULL)
//   EVP_CIPHER_CTX_ctrl(IVLEN, 12)
//   EVP_DecryptInit_ex(cipher=NULL, key=32B, iv=12B)
//   EVP_CIPHER_CTX_ctrl(SET_TAG, 16, expected_tag)  ← BEFORE plaintext
//   EVP_DecryptUpdate(out=NULL, aad)
//   EVP_DecryptUpdate(out=plaintext_buf, ciphertext)
//   EVP_DecryptFinal_ex(scratch)               ← returns 1 on auth success
//   On failure: zero plaintext_buf → throw AuthenticationError
//
// Security invariants enforced here:
//   - Temporary ChaCha20 key is always zeroed after use (try/catch on all paths)
//   - OpenSSL EVP context is freed via RAII (EvpCtxPtr), which calls
//     EVP_CIPHER_CTX_reset, zeroing internal key material
//   - Plaintext is never returned to the caller on authentication failure
//   - AeadCipher state is rolled back on authentication failure (D7)

#include "eahcm/aead.hpp"
#include "eahcm/detail/evp_ctx.hpp"
#include "eahcm/state.hpp"         // step(), extract()
#include "eahcm/key_schedule.hpp"  // derive_state()

#include <openssl/evp.h>

#include <cassert>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

// =========================================================================
// File-scope helpers (not part of the public API)
// =========================================================================

/// Throw KeyError if the ChaCha20 nonce is not exactly AEAD_NONCE_SIZE bytes.
inline void validate_chacha_nonce(std::span<const std::uint8_t> nonce) {
    if (nonce.size() != eahcm::AEAD_NONCE_SIZE)
        throw eahcm::KeyError(
            "ChaCha20-Poly1305 nonce must be exactly 12 bytes (got " +
            std::to_string(nonce.size()) + ")");
}

/// Throw KeyError if the Poly1305 tag is not exactly AEAD_TAG_SIZE bytes.
inline void validate_poly1305_tag(std::span<const std::uint8_t> tag) {
    if (tag.size() != eahcm::AEAD_TAG_SIZE)
        throw eahcm::KeyError(
            "Poly1305 tag must be exactly 16 bytes (got " +
            std::to_string(tag.size()) + ")");
}

/// Throw std::overflow_error if size exceeds INT_MAX.
inline void validate_message_size(std::size_t size, const char* what) {
    if (size > eahcm::AEAD_MAX_MESSAGE_BYTES)
        throw std::overflow_error(
            std::string(what) + " size exceeds maximum (~2 GiB per AEAD call)");
}

/// Throw CryptoError with a descriptive message.
[[noreturn]] inline void throw_crypto_error(const char* where) {
    throw eahcm::CryptoError(
        std::string("OpenSSL EVP error in ") + where);
}

// =========================================================================
// Raw ChaCha20-Poly1305 encrypt (RFC 8439) via OpenSSL EVP
// =========================================================================
//
// Preconditions (checked by callers):
//   key.size()   == AEAD_KEY_SIZE   (32)
//   nonce.size() == AEAD_NONCE_SIZE (12)
//   plaintext.size() <= AEAD_MAX_MESSAGE_BYTES
//
eahcm::AeadPacket evp_encrypt_raw(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext)
{
    using namespace eahcm;
    using namespace eahcm::detail;

    auto ctx = make_evp_ctx();

    // Step 1: initialize the ChaCha20-Poly1305 cipher (no key/iv yet)
    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
                           nullptr, nullptr, nullptr) != 1)
        throw_crypto_error("EVP_EncryptInit_ex (cipher select)");

    // Step 2: set nonce length to 12 (standard for ChaCha20-Poly1305)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                             static_cast<int>(AEAD_NONCE_SIZE), nullptr) != 1)
        throw_crypto_error("EVP_CIPHER_CTX_ctrl (IVLEN)");

    // Step 3: supply key and nonce
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           key.data(), nonce.data()) != 1)
        throw_crypto_error("EVP_EncryptInit_ex (key/iv)");

    // Step 4: supply AAD (null output pointer signals AAD mode)
    if (!aad.empty()) {
        int aad_outl = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_outl,
                              aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw_crypto_error("EVP_EncryptUpdate (AAD)");
    }

    // Step 5: encrypt plaintext
    AeadPacket result;
    // Pre-allocate: ChaCha20 is a stream cipher; output == input length.
    // +16 safety margin for EVP_EncryptFinal_ex (should be 0 for stream cipher).
    const std::size_t ct_buf_size = plaintext.size() + 16;
    result.ciphertext.resize(ct_buf_size);

    int ct_outl = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &ct_outl,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
            throw_crypto_error("EVP_EncryptUpdate (plaintext)");
    }

    // Step 6: finalize (stream cipher → 0 bytes output; still required)
    int final_outl = 0;
    if (EVP_EncryptFinal_ex(ctx.get(),
                             result.ciphertext.data() + ct_outl,
                             &final_outl) != 1)
        throw_crypto_error("EVP_EncryptFinal_ex");

    result.ciphertext.resize(
        static_cast<std::size_t>(ct_outl) +
        static_cast<std::size_t>(final_outl));

    // Step 7: extract Poly1305 tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                             static_cast<int>(AEAD_TAG_SIZE),
                             result.tag.data()) != 1)
        throw_crypto_error("EVP_CIPHER_CTX_ctrl (GET_TAG)");

    return result;
    // ctx goes out of scope here → EVP_CIPHER_CTX_free → zeroes OpenSSL state
}

// =========================================================================
// Raw ChaCha20-Poly1305 decrypt (RFC 8439, verify-before-use) via OpenSSL EVP
// =========================================================================
//
// Preconditions (checked by callers):
//   key.size()   == AEAD_KEY_SIZE   (32)
//   nonce.size() == AEAD_NONCE_SIZE (12)
//   tag.size()   == AEAD_TAG_SIZE   (16)
//   ciphertext.size() <= AEAD_MAX_MESSAGE_BYTES
//
// Security invariant:
//   If EVP_DecryptFinal_ex returns != 1 (tag mismatch), the temporary
//   plaintext buffer is explicitly zeroed before throwing AuthenticationError.
//
std::vector<std::uint8_t> evp_decrypt_raw(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> tag)
{
    using namespace eahcm;
    using namespace eahcm::detail;

    auto ctx = make_evp_ctx();

    // Step 1: initialize ChaCha20-Poly1305 for decryption
    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
                           nullptr, nullptr, nullptr) != 1)
        throw_crypto_error("EVP_DecryptInit_ex (cipher select)");

    // Step 2: set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                             static_cast<int>(AEAD_NONCE_SIZE), nullptr) != 1)
        throw_crypto_error("EVP_CIPHER_CTX_ctrl (IVLEN)");

    // Step 3: supply key and nonce
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           key.data(), nonce.data()) != 1)
        throw_crypto_error("EVP_DecryptInit_ex (key/iv)");

    // Step 4: set the expected tag BEFORE processing ciphertext.
    //
    // This is the mandatory ordering for OpenSSL AEAD decryption.
    // The cast to (void*) is required by the OpenSSL C API (EVP_CIPHER_CTX_ctrl
    // uses void* for both read and write operations); we only read from it here.
    //
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto* tag_ptr = const_cast<std::uint8_t*>(tag.data());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                             static_cast<int>(AEAD_TAG_SIZE),
                             static_cast<void*>(tag_ptr)) != 1)
        throw_crypto_error("EVP_CIPHER_CTX_ctrl (SET_TAG)");

    // Step 5: process AAD
    if (!aad.empty()) {
        int aad_outl = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_outl,
                              aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw_crypto_error("EVP_DecryptUpdate (AAD)");
    }

    // Step 6: decrypt ciphertext into a temporary buffer.
    //
    // The decrypted bytes are held here until authentication is verified.
    // They are NEVER returned to the caller unless authentication succeeds.
    std::vector<std::uint8_t> plaintext;
    plaintext.resize(ciphertext.size() + 16); // +16 safety margin

    int pt_outl = 0;
    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &pt_outl,
                              ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != 1)
            throw_crypto_error("EVP_DecryptUpdate (ciphertext)");
    }

    // Step 7: finalize — THIS IS WHERE POLY1305 TAG VERIFICATION OCCURS.
    //
    // EVP_DecryptFinal_ex returns 1 on authentication success, <= 0 on failure.
    // Do NOT skip this call. Do NOT ignore the return value.
    int final_outl = 0;
    const int auth_result = EVP_DecryptFinal_ex(
        ctx.get(),
        plaintext.data() + pt_outl,
        &final_outl);

    if (auth_result != 1) {
        // Authentication FAILED.
        // Zero the temporary plaintext immediately — it must not leak.
        EAHCM_SECURE_ZERO(plaintext.data(), plaintext.size());
        throw AuthenticationError(
            "ChaCha20-Poly1305 authentication failed: tag mismatch");
    }

    // Authentication succeeded — trim to actual size and return.
    plaintext.resize(
        static_cast<std::size_t>(pt_outl) +
        static_cast<std::size_t>(final_outl));
    return plaintext;
    // ctx out of scope → EVP_CIPHER_CTX_free → zeroes OpenSSL state
}

} // anonymous namespace

// =========================================================================
// Public API implementation
// =========================================================================

namespace eahcm {

// -------------------------------------------------------------------------
// derive_chacha_key
// -------------------------------------------------------------------------

std::array<std::uint8_t, AEAD_KEY_SIZE>
derive_chacha_key(State& s) noexcept {
    // Protocol (decision D1):
    //   For i = 0, 1, 2, 3:
    //     step(s)          — advance chaotic state
    //     word = extract(s) — 64-bit output
    //     key[i*8..i*8+7]  = word serialized as little-endian bytes
    //
    // LE serialization ensures platform-independent output.
    // extract() returns (out_hi << 32) | out_lo; our byte loop extracts
    // bytes from bit 0 (LSB) upward, which is standard little-endian.

    std::array<std::uint8_t, AEAD_KEY_SIZE> key{};
    for (std::size_t i = 0; i < AEAD_SEED_STEPS; ++i) {
        step(s);
        const std::uint64_t word = extract(s);
        for (int b = 0; b < 8; ++b) {
            key[i * 8u + static_cast<std::size_t>(b)] =
                static_cast<std::uint8_t>(word >> (b * 8));
        }
    }
    return key;
}

// -------------------------------------------------------------------------
// aead_encrypt (stateless)
// -------------------------------------------------------------------------

AeadPacket
aead_encrypt(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> eahcm_nonce,
             std::span<const std::uint8_t> chacha_nonce,
             std::span<const std::uint8_t> aad,
             std::span<const std::uint8_t> plaintext) {
    if (user_key.empty())
        throw KeyError("aead_encrypt: user_key must not be empty");
    validate_chacha_nonce(chacha_nonce);
    validate_message_size(plaintext.size(), "plaintext");
    if (!aad.empty()) validate_message_size(aad.size(), "AAD");

    // Derive fresh EAHCM state — stack-local, zeroed on exit
    State s = derive_state(user_key, eahcm_nonce);

    // Derive the ChaCha20 key (decision D1)
    auto chacha_key = derive_chacha_key(s);
    s.secure_wipe();  // EAHCM state no longer needed

    AeadPacket result;
    try {
        result = evp_encrypt_raw(chacha_key, chacha_nonce, aad, plaintext);
    } catch (...) {
        EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
        throw;
    }
    EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
    return result;
}

// -------------------------------------------------------------------------
// aead_decrypt (stateless)
// -------------------------------------------------------------------------

std::vector<std::uint8_t>
aead_decrypt(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> eahcm_nonce,
             std::span<const std::uint8_t> chacha_nonce,
             std::span<const std::uint8_t> aad,
             std::span<const std::uint8_t> ciphertext,
             std::span<const std::uint8_t> tag) {
    if (user_key.empty())
        throw KeyError("aead_decrypt: user_key must not be empty");
    validate_chacha_nonce(chacha_nonce);
    validate_poly1305_tag(tag);
    validate_message_size(ciphertext.size(), "ciphertext");
    if (!aad.empty()) validate_message_size(aad.size(), "AAD");

    // Derive fresh EAHCM state — must mirror aead_encrypt exactly
    State s = derive_state(user_key, eahcm_nonce);

    auto chacha_key = derive_chacha_key(s);
    s.secure_wipe();

    std::vector<std::uint8_t> plaintext;
    try {
        // evp_decrypt_raw enforces verify-before-use (decision D5)
        plaintext = evp_decrypt_raw(chacha_key, chacha_nonce, aad,
                                     ciphertext, tag);
    } catch (...) {
        EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
        throw;
    }
    EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
    return plaintext;
}

// =========================================================================
// AeadCipher implementation
// =========================================================================

AeadCipher::AeadCipher(std::span<const std::uint8_t> key,
                       std::span<const std::uint8_t> eahcm_nonce,
                       std::span<const std::uint8_t> info) {
    if (key.empty())
        throw KeyError("AeadCipher: key must not be empty");
    state_ = derive_state(key, eahcm_nonce, {}, info);
    initial_state_ = state_;
    // Raw key/nonce/info are NOT stored (decision D10); only the derived
    // post-warmup state is retained for later reset().
}

AeadCipher::~AeadCipher() {
    state_.secure_wipe();
    initial_state_.secure_wipe();
}

AeadCipher::AeadCipher(AeadCipher&& other) noexcept
    : state_(other.state_), initial_state_(other.initial_state_) {
    // Wipe the source to prevent dual use of the same key material
    other.state_.secure_wipe();
    other.initial_state_.secure_wipe();
}

AeadCipher& AeadCipher::operator=(AeadCipher&& other) noexcept {
    if (this != &other) {
        state_.secure_wipe();
        initial_state_.secure_wipe();
        state_ = other.state_;
        initial_state_ = other.initial_state_;
        other.state_.secure_wipe();
        other.initial_state_.secure_wipe();
    }
    return *this;
}

// -------------------------------------------------------------------------
// AeadCipher::encrypt
// -------------------------------------------------------------------------

AeadPacket
AeadCipher::encrypt(std::span<const std::uint8_t> chacha_nonce,
                    std::span<const std::uint8_t> aad,
                    std::span<const std::uint8_t> plaintext) {
    validate_chacha_nonce(chacha_nonce);
    validate_message_size(plaintext.size(), "plaintext");
    if (!aad.empty()) validate_message_size(aad.size(), "AAD");

    // Derive ChaCha20 key from current EAHCM state.
    // This advances state_ by AEAD_SEED_STEPS (4 steps) — decision D6.
    auto chacha_key = derive_chacha_key(state_);

    AeadPacket result;
    try {
        result = evp_encrypt_raw(chacha_key, chacha_nonce, aad, plaintext);
    } catch (...) {
        EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
        throw;
    }
    EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
    return result;
}

// -------------------------------------------------------------------------
// AeadCipher::decrypt
// -------------------------------------------------------------------------

std::vector<std::uint8_t>
AeadCipher::decrypt(std::span<const std::uint8_t> chacha_nonce,
                    std::span<const std::uint8_t> aad,
                    std::span<const std::uint8_t> ciphertext,
                    std::span<const std::uint8_t> tag) {
    validate_chacha_nonce(chacha_nonce);
    validate_poly1305_tag(tag);
    validate_message_size(ciphertext.size(), "ciphertext");
    if (!aad.empty()) validate_message_size(aad.size(), "AAD");

    // Save current state for rollback on authentication failure (decision D7).
    // If EVP_DecryptFinal_ex fails (tag mismatch), the state_ is restored
    // so the AeadCipher remains synchronized with the encryptor — the
    // caller can attempt decryption of the same message again (e.g. after
    // correcting the nonce or AAD).
    const State saved_state = state_;

    auto chacha_key = derive_chacha_key(state_); // advances state_

    std::vector<std::uint8_t> plaintext;
    try {
        plaintext = evp_decrypt_raw(chacha_key, chacha_nonce, aad,
                                     ciphertext, tag);
    } catch (...) {
        // Roll back state_ on any error (auth or crypto) — decision D7
        state_ = saved_state;
        EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
        throw;
    }

    EAHCM_SECURE_ZERO(chacha_key.data(), chacha_key.size());
    // saved_state is a stack local; it will be destroyed here.
    // For defence-in-depth, explicitly zero it since it contains key material.
    const_cast<State&>(saved_state).secure_wipe();
    return plaintext;
}

// -------------------------------------------------------------------------
// AeadCipher::seal
// -------------------------------------------------------------------------

std::vector<std::uint8_t>
AeadCipher::seal(std::span<const std::uint8_t> chacha_nonce,
                 std::span<const std::uint8_t> aad,
                 std::span<const std::uint8_t> plaintext) {
    auto [ct, tag] = encrypt(chacha_nonce, aad, plaintext);

    // Container format (decision D8):
    //   [1B version][12B nonce][8B ciphertext_len LE][ciphertext][16B tag]
    const std::uint64_t ct_len = static_cast<std::uint64_t>(ct.size());

    std::vector<std::uint8_t> out;
    out.reserve(CONTAINER_MIN_SIZE + ct.size());

    out.push_back(CONTAINER_VERSION);

    // Embed chacha_nonce (12 bytes)
    out.insert(out.end(), chacha_nonce.begin(), chacha_nonce.end());

    // Embed ciphertext_length as uint64_t LE
    for (int b = 0; b < 8; ++b)
        out.push_back(static_cast<std::uint8_t>(ct_len >> (b * 8)));

    // Embed ciphertext
    out.insert(out.end(), ct.begin(), ct.end());

    // Embed tag
    out.insert(out.end(), tag.begin(), tag.end());

    return out;
}

// -------------------------------------------------------------------------
// AeadCipher::open
// -------------------------------------------------------------------------

std::vector<std::uint8_t>
AeadCipher::open(std::span<const std::uint8_t> sealed_data,
                 std::span<const std::uint8_t> aad) {
    // Minimum: 1 (ver) + 12 (nonce) + 8 (len) + 0 (empty ct) + 16 (tag)
    if (sealed_data.size() < CONTAINER_MIN_SIZE)
        throw SerializationError(
            "AeadCipher::open: sealed blob is too small (got " +
            std::to_string(sealed_data.size()) + " bytes, minimum " +
            std::to_string(CONTAINER_MIN_SIZE) + ")");

    const std::uint8_t* p = sealed_data.data();

    // Version check
    const std::uint8_t ver = *p++;
    if (ver != CONTAINER_VERSION)
        throw SerializationError(
            "AeadCipher::open: unsupported container version " +
            std::to_string(static_cast<int>(ver)) +
            " (expected " + std::to_string(static_cast<int>(CONTAINER_VERSION)) + ")");

    // Parse nonce (12 bytes)
    const std::span<const std::uint8_t> nonce_span(p, AEAD_NONCE_SIZE);
    p += AEAD_NONCE_SIZE;

    // Parse ciphertext_length (uint64_t LE)
    std::uint64_t ct_len = 0;
    for (int b = 0; b < 8; ++b)
        ct_len |= (static_cast<std::uint64_t>(*p++) << (b * 8));

    // Validate ciphertext_length against remaining blob size
    const std::size_t remaining = sealed_data.size() -
                                   (1u + AEAD_NONCE_SIZE + 8u);
    if (ct_len > remaining || remaining - ct_len < AEAD_TAG_SIZE)
        throw SerializationError(
            "AeadCipher::open: malformed container: ciphertext_length inconsistent");

    // Extract ciphertext and tag
    const std::span<const std::uint8_t> ct_span(p, static_cast<std::size_t>(ct_len));
    p += static_cast<std::size_t>(ct_len);
    const std::span<const std::uint8_t> tag_span(p, AEAD_TAG_SIZE);

    // Decrypt (authentication happens inside)
    return decrypt(nonce_span, aad, ct_span, tag_span);
}

// -------------------------------------------------------------------------
// AeadCipher::reset
// -------------------------------------------------------------------------

void AeadCipher::reset() {
    state_ = initial_state_;
}

} // namespace eahcm
