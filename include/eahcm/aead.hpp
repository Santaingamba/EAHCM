// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// aead.hpp — Stage 2: ChaCha20-Poly1305 AEAD construction.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │  PUBLIC API HEADER — safe to include from user code                 │
// └─────────────────────────────────────────────────────────────────────┘
//
// Architecture (Stage 2 construction)
// ─────────────────────────────────────
//
//   USER KEY + EAHCM_NONCE
//           │
//   HKDF-SHA3-256  (key_schedule.hpp — unchanged from Stage 1)
//           │
//   EAHCM INITIAL STATE  (256-step warmup)
//           │
//   step(s) + extract(s) × 4  ──→  32-byte CHACHA20 KEY
//           │                              (derive_chacha_key)
//   ChaCha20-Poly1305 (OpenSSL EVP, RFC 8439)
//   key=32B  chacha_nonce=12B  aad=arbitrary  plaintext
//           │
//   CIPHERTEXT + 16-byte Poly1305 TAG
//
// Design decisions (see implementation_plan.md for rationale)
// ──────────────────────────────────────────────────────────────
//   D1  ChaCha key = 4 × (step+extract), LE-serialized
//   D2  Two distinct nonces: EAHCM nonce (HKDF) vs. ChaCha nonce (AEAD)
//   D3  No plaintext-hash mixing — decryptor cannot reconstruct it
//   D4  RFC 8439 EVP_chacha20_poly1305 semantics throughout
//   D5  Verify-before-use: plaintext never returned on auth failure
//   D6  Natural per-call rekeying: EAHCM state advances 4 steps per call
//   D7  State rollback on authentication failure (AeadCipher::decrypt)
//   D8  Container format: [1B ver][12B nonce][8B len LE][ct][16B tag]
//   D9  AAD authenticated but NOT embedded in container; caller re-supplies
//   D10 AeadCipher stores state_ + initial_state_ only (no raw key bytes)
//
// Nonce reuse warning
// ────────────────────
//   For the STATELESS free functions (aead_encrypt / aead_decrypt):
//     Using the same (user_key, eahcm_nonce, chacha_nonce) triple for
//     two different messages WILL reuse a ChaCha20 (key, nonce) pair,
//     completely breaking confidentiality.  The caller is responsible
//     for uniqueness.
//
//   For the STATEFUL AeadCipher class:
//     Each call to encrypt() / decrypt() advances the EAHCM state by 4
//     steps, producing a fresh ChaCha20 key.  Even if the caller
//     accidentally reuses the chacha_nonce, the effective (key, nonce)
//     pair is still unique.  Nonetheless, callers SHOULD use unique
//     chacha_nonces as a defence-in-depth measure.
//
// Security assumptions
// ─────────────────────
//   - Confidentiality: ChaCha20 stream-cipher hardness assumption
//   - Authenticity:    Poly1305 one-time MAC security assumption
//   - Key derivation:  HKDF-SHA3-256 PRF assumption
//   - No claim is made that EAHCM chaotic properties provide
//     additional cryptographic hardness beyond the above.
//
// OpenSSL compatibility
// ──────────────────────
//   Requires OpenSSL 1.1.0 or later (EVP_chacha20_poly1305 is available
//   from 1.1.0).  Tested with OpenSSL 3.x; the underlying AEAD
//   primitive is not deprecated.

#ifndef EAHCM_AEAD_HPP
#define EAHCM_AEAD_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include "eahcm/config.hpp"
#include "eahcm/types.hpp"
#include "eahcm/exceptions.hpp"

namespace eahcm {

// =========================================================================
// Constants
// =========================================================================

/// Size of the ChaCha20 key (256 bits).
inline constexpr std::size_t AEAD_KEY_SIZE = 32;

/// Size of the ChaCha20-Poly1305 nonce (96 bits).
inline constexpr std::size_t AEAD_NONCE_SIZE = 12;

/// Size of the Poly1305 authentication tag (128 bits).
inline constexpr std::size_t AEAD_TAG_SIZE = 16;

/// Number of EAHCM (step + extract) iterations used to fill one ChaCha20 key.
inline constexpr std::size_t AEAD_SEED_STEPS = 4;

/// Maximum plaintext/ciphertext length per AEAD call.
///
/// Limited to INT_MAX bytes because OpenSSL EVP APIs use int for lengths.
/// Messages larger than this limit must be split by the caller.
/// (Approximately 2 GiB on all supported platforms.)
inline constexpr std::size_t AEAD_MAX_MESSAGE_BYTES =
    static_cast<std::size_t>((std::numeric_limits<int>::max)());

/// Version tag embedded in the container format produced by seal().
inline constexpr std::uint8_t CONTAINER_VERSION = 2;

/// Minimum size of a container blob produced by seal().
///
/// = 1 (version) + 12 (nonce) + 8 (ciphertext_len) + 0 (empty ct) + 16 (tag)
inline constexpr std::size_t CONTAINER_MIN_SIZE =
    1 + AEAD_NONCE_SIZE + 8 + AEAD_TAG_SIZE;

// =========================================================================
// AeadPacket — result type for encrypt()
// =========================================================================

/// Result of an AEAD encryption operation.
///
/// - ciphertext: same length as the plaintext (ChaCha20 is a stream cipher)
/// - tag:        16-byte Poly1305 authentication tag
///
/// Both fields must be transmitted/stored together and supplied verbatim
/// to the corresponding decrypt() call.
struct AeadPacket {
    std::vector<std::uint8_t>               ciphertext;
    std::array<std::uint8_t, AEAD_TAG_SIZE> tag{};
};

// =========================================================================
// Low-level seed derivation (public for testing / interoperability)
// =========================================================================

/// Derive a 32-byte ChaCha20 seed from the EAHCM state.
///
/// Performs AEAD_SEED_STEPS (4) iterations of step(s) + extract(s) and
/// serializes the four 64-bit extractions as little-endian bytes.
///
/// Protocol (decision D1):
///   For i in {0, 1, 2, 3}:
///     step(s)
///     word_i = extract(s)                // uint64_t
///     seed[i*8 .. i*8+7] = LE(word_i)   // 8 bytes, little-endian
///
/// This function ADVANCES s by 4 steps.  Callers that need the key
/// without advancing state should work on a copy of s.
///
/// Platform independence:
///   The same user_key + eahcm_nonce on any supported platform produces
///   the identical 32-byte seed because:
///     (a) HKDF-SHA3-256 is deterministic and platform-independent,
///     (b) step() / extract() use only addition, XOR, and rotations,
///     (c) the LE serialization is explicit, not host-endian memcpy.
///
/// @param s  EAHCM state — modified in place (advanced by AEAD_SEED_STEPS).
/// @return   32-byte ChaCha20 key.
[[nodiscard]] EAHCM_API std::array<std::uint8_t, AEAD_KEY_SIZE>
derive_chacha_key(State& s) noexcept;

// =========================================================================
// Stateless one-shot AEAD functions
// =========================================================================

/// One-shot AEAD encryption (stateless).
///
/// Derives a fresh EAHCM state from (user_key, eahcm_nonce), extracts a
/// 32-byte ChaCha20 key, then runs ChaCha20-Poly1305 (RFC 8439) over
/// (chacha_nonce, aad, plaintext).
///
/// Nonce reuse warning (decision D2):
///   The triple (user_key, eahcm_nonce, chacha_nonce) must be unique
///   per message.  Reuse completely destroys confidentiality.
///
/// @param user_key      Raw secret key (must be non-empty).
/// @param eahcm_nonce   EAHCM initialization nonce fed to HKDF (any length).
/// @param chacha_nonce  12-byte ChaCha20-Poly1305 nonce (must be unique).
/// @param aad           Additional authenticated data (may be empty).
/// @param plaintext     Message to encrypt (max AEAD_MAX_MESSAGE_BYTES).
/// @return AeadPacket   ciphertext + 16-byte Poly1305 tag.
/// @throws KeyError     if user_key is empty or chacha_nonce.size() != 12.
/// @throws CryptoError  if the OpenSSL EVP operation fails unexpectedly.
[[nodiscard]] EAHCM_API AeadPacket
aead_encrypt(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> eahcm_nonce,
             std::span<const std::uint8_t> chacha_nonce,
             std::span<const std::uint8_t> aad,
             std::span<const std::uint8_t> plaintext);

/// One-shot AEAD decryption (stateless).
///
/// Mirrors aead_encrypt() exactly.  The Poly1305 tag is verified FIRST;
/// plaintext is only returned if authentication succeeds.
///
/// @param user_key      Raw secret key (must be non-empty).
/// @param eahcm_nonce   EAHCM initialization nonce (must match encrypt).
/// @param chacha_nonce  12-byte ChaCha20-Poly1305 nonce (must match encrypt).
/// @param aad           Additional authenticated data (must match encrypt).
/// @param ciphertext    Encrypted message bytes.
/// @param tag           16-byte Poly1305 tag from aead_encrypt().
/// @return              Decrypted plaintext.
/// @throws AuthenticationError  if tag does not match (no plaintext returned).
/// @throws KeyError             if user_key is empty or nonce/tag sizes wrong.
/// @throws CryptoError          if the OpenSSL EVP operation fails.
[[nodiscard]] EAHCM_API std::vector<std::uint8_t>
aead_decrypt(std::span<const std::uint8_t> user_key,
             std::span<const std::uint8_t> eahcm_nonce,
             std::span<const std::uint8_t> chacha_nonce,
             std::span<const std::uint8_t> aad,
             std::span<const std::uint8_t> ciphertext,
             std::span<const std::uint8_t> tag);

// =========================================================================
// AeadCipher — stateful AEAD class
// =========================================================================

/// Stateful EAHCM + ChaCha20-Poly1305 AEAD cipher.
///
/// Wraps an EAHCM state (derived via existing key schedule) and provides
/// authenticated encryption / decryption using ChaCha20-Poly1305 (RFC 8439).
///
/// Each call to encrypt() / decrypt() advances the internal EAHCM state
/// by AEAD_SEED_STEPS (4) steps, producing a fresh ChaCha20 key.  This
/// provides natural per-message rekeying without any separate mechanism.
///
/// Encryptor/decryptor sync requirement:
///   If both sides use AeadCipher initialized with the same (key,
///   eahcm_nonce), they must call encrypt / decrypt in the same order.
///   State advances unconditionally on both sides.
///   If an authentication failure occurs, the internal state is ROLLED BACK
///   (decision D7) so the decryptor can attempt the same message again.
///
/// Container format:
///   Use seal() / open() instead of encrypt() / decrypt() when you want
///   the library to handle nonce embedding and format parsing.
///
/// Thread safety:
///   Independent AeadCipher instances are fully thread-safe.
///   A single instance is NOT thread-safe; use external synchronisation
///   or one instance per thread.
///
/// Move-only:
///   Copying is disabled to prevent accidental duplication of key material.
class EAHCM_API AeadCipher {
public:
    /// Construct an AeadCipher from a user key and EAHCM initialization nonce.
    ///
    /// Performs full HKDF-SHA3-256 key derivation and 256-step EAHCM warmup.
    ///
    /// @param key          Raw secret key (must be non-empty).
    /// @param eahcm_nonce  EAHCM initialization nonce (12 bytes recommended).
    /// @param info         Domain-separation context (default: "EAHCM-v1").
    /// @throws KeyError if key is empty.
    AeadCipher(std::span<const std::uint8_t> key,
               std::span<const std::uint8_t> eahcm_nonce,
               std::span<const std::uint8_t> info = {});

    /// Destructor — securely wipes all state material.
    ~AeadCipher();

    // Move-only
    AeadCipher(const AeadCipher&) = delete;
    AeadCipher& operator=(const AeadCipher&) = delete;
    AeadCipher(AeadCipher&&) noexcept;
    AeadCipher& operator=(AeadCipher&&) noexcept;

    // ---- Encrypt / Decrypt ----

    /// Encrypt plaintext and authenticate with AAD.
    ///
    /// Advances the internal EAHCM state by AEAD_SEED_STEPS to derive a
    /// fresh ChaCha20 key, then performs ChaCha20-Poly1305 encryption.
    ///
    /// chacha_nonce must be unique for each call under this AeadCipher
    /// instance.  Because the EAHCM state advances per call, accidental
    /// chacha_nonce reuse does NOT reuse the effective (key, nonce) pair,
    /// but unique nonces are still strongly recommended (defence-in-depth).
    ///
    /// @param chacha_nonce  12-byte ChaCha20-Poly1305 nonce (unique per call).
    /// @param aad           Additional authenticated data (may be empty).
    /// @param plaintext     Message to encrypt (max AEAD_MAX_MESSAGE_BYTES).
    /// @return AeadPacket   ciphertext + 16-byte tag.
    /// @throws KeyError    if chacha_nonce is not exactly 12 bytes.
    /// @throws CryptoError if the EVP operation fails.
    [[nodiscard]] AeadPacket
    encrypt(std::span<const std::uint8_t> chacha_nonce,
            std::span<const std::uint8_t> aad,
            std::span<const std::uint8_t> plaintext);

    /// Decrypt and authenticate ciphertext.
    ///
    /// Advances the internal EAHCM state by AEAD_SEED_STEPS to derive the
    /// same ChaCha20 key as the corresponding encrypt() call.
    ///
    /// Authentication failure (decision D5 + D7):
    ///   If the tag does not match, AuthenticationError is thrown and:
    ///     - No plaintext is returned
    ///     - The internal EAHCM state is ROLLED BACK to its pre-call value
    ///       so the object remains usable
    ///
    /// @param chacha_nonce  12-byte nonce (must match encrypt).
    /// @param aad           AAD (must match encrypt).
    /// @param ciphertext    Encrypted bytes from encrypt().
    /// @param tag           16-byte tag from encrypt().
    /// @return              Decrypted plaintext.
    /// @throws AuthenticationError  if authentication fails (no plaintext).
    /// @throws KeyError             if chacha_nonce or tag size is wrong.
    /// @throws CryptoError          if the EVP operation fails.
    [[nodiscard]] std::vector<std::uint8_t>
    decrypt(std::span<const std::uint8_t> chacha_nonce,
            std::span<const std::uint8_t> aad,
            std::span<const std::uint8_t> ciphertext,
            std::span<const std::uint8_t> tag);

    // ---- Container format: seal / open ----

    /// Encrypt and serialize into a self-contained blob (decision D8).
    ///
    /// Container wire format (all multi-byte fields little-endian):
    ///   Byte  0     : version (= CONTAINER_VERSION = 2)
    ///   Bytes 1-12  : chacha_nonce (12 bytes verbatim)
    ///   Bytes 13-20 : ciphertext_length (uint64_t LE)
    ///   Bytes 21..N : ciphertext (N bytes)
    ///   Last 16     : Poly1305 tag
    ///
    /// AAD is NOT embedded in the container (decision D9); the caller must
    /// supply it identically to open().
    ///
    /// @param chacha_nonce  12-byte nonce (unique per call).
    /// @param aad           Additional authenticated data (not stored).
    /// @param plaintext     Message to encrypt.
    /// @return              Self-contained sealed blob.
    [[nodiscard]] std::vector<std::uint8_t>
    seal(std::span<const std::uint8_t> chacha_nonce,
         std::span<const std::uint8_t> aad,
         std::span<const std::uint8_t> plaintext);

    /// Parse, authenticate, and decrypt a sealed blob.
    ///
    /// Performs full format validation before decryption:
    ///   1. Check minimum size
    ///   2. Check version byte
    ///   3. Validate ciphertext_length against actual blob size
    ///   4. Call decrypt() — authentication happens inside EVP
    ///
    /// @param sealed_data  Blob produced by seal().
    /// @param aad          AAD (must match the aad supplied to seal()).
    /// @return             Decrypted plaintext.
    /// @throws SerializationError   if the blob is malformed or version mismatch.
    /// @throws AuthenticationError  if tag verification fails.
    /// @throws CryptoError          if EVP operation fails.
    [[nodiscard]] std::vector<std::uint8_t>
    open(std::span<const std::uint8_t> sealed_data,
         std::span<const std::uint8_t> aad);

    // ---- State management ----

    /// Reset the EAHCM state to the initial warmed-up state.
    ///
    /// After reset(), the next encrypt() / decrypt() call will use the
    /// same ChaCha20 key as the very first call.
    ///
    /// Security note: resetting and re-using the same chacha_nonce for
    /// the same message creates a keystream reuse — do not do this.
    void reset();

private:
    State state_{};          ///< Current EAHCM state (advances per call)
    State initial_state_{};  ///< Stored for reset()
};

} // namespace eahcm

#endif // EAHCM_AEAD_HPP
