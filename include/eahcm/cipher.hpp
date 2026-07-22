// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// cipher.hpp — High-level public API for the EAHCM cipher.
//
// This is the main entry point for users of the library.
// Wraps the internal State with RAII, secure zeroisation, and
// a clean interface for keystream generation.

#ifndef EAHCM_CIPHER_HPP
#define EAHCM_CIPHER_HPP

#include <cstdint>
#include <span>
#include <string>
#include <array>
#include <vector>

#include "eahcm/config.hpp"
#include "eahcm/types.hpp"
#include "eahcm/state.hpp"
#include "eahcm/key_schedule.hpp"
#include "eahcm/serialization.hpp"
#include "eahcm/exceptions.hpp"

namespace eahcm {

/// High-level EAHCM cipher interface.
///
/// Usage:
///   Cipher cipher(key, nonce);
///   cipher.generate(output_span);
///   cipher.reset();
///
/// Thread safety:
///   Independent Cipher instances are thread-safe.
///   A single Cipher instance must not be shared between threads
///   without external synchronisation.
///
/// Memory safety:
///   - State is securely wiped on destruction.
///   - No raw pointers or manual memory management.
///   - Move-only (no accidental copies of key material).
class EAHCM_API Cipher {
public:
    /// Construct a cipher from raw key and nonce bytes.
    ///
    /// Performs full key derivation and 256-step warmup.
    ///
    /// @param key    Raw secret key (any length, must be non-empty).
    /// @param nonce  Unique per-message value (12 bytes recommended).
    /// @param info   Domain-separation context (default: "EAHCM-v1").
    /// @throws KeyError if key is empty.
    Cipher(std::span<const std::uint8_t> key,
           std::span<const std::uint8_t> nonce,
           std::span<const std::uint8_t> info = {});

    /// Destructor — securely wipes all state material.
    ~Cipher();

    // Move-only: prevent accidental copies of key material.
    Cipher(const Cipher&) = delete;
    Cipher& operator=(const Cipher&) = delete;
    Cipher(Cipher&& other) noexcept;
    Cipher& operator=(Cipher&& other) noexcept;

    /// Generate keystream bytes into the provided buffer.
    ///
    /// Each call advances the state and fills output with
    /// extracted keystream. Partial 64-bit words are buffered
    /// internally for subsequent calls.
    ///
    /// @param output  Buffer to fill with keystream bytes.
    void generate(std::span<std::uint8_t> output);

    /// Generate exactly N bytes of keystream.
    ///
    /// @param count  Number of bytes to generate.
    /// @return       Vector of keystream bytes.
    [[nodiscard]] std::vector<std::uint8_t> generate(std::size_t count);

    /// Advance the state by one step and return the 64-bit keystream word.
    [[nodiscard]] std::uint64_t next();

    /// Reset the cipher to the initial warmed-up state.
    ///
    /// Requires that the original key material was stored.
    /// After reset, generate() produces the same keystream.
    void reset();

    /// Re-seed the cipher with a new key and nonce.
    ///
    /// Securely wipes the old state before initializing with new material.
    void reseed(std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> info = {});

    /// Export the current state as a binary blob.
    [[nodiscard]] std::array<std::uint8_t, SERIALIZED_BINARY_SIZE>
    export_state() const;

    /// Import state from a binary blob.
    ///
    /// @throws SerializationError on version mismatch or checksum failure.
    void import_state(std::span<const std::uint8_t, SERIALIZED_BINARY_SIZE> data);

    /// Export the current state as a JSON string.
    [[nodiscard]] std::string export_state_json(bool pretty = true) const;

    /// Import state from a JSON string.
    ///
    /// @throws SerializationError on parse error or validation failure.
    void import_state_json(std::string_view json);

    /// Get a read-only view of the current state (for testing/introspection).
    [[nodiscard]] const State& state() const noexcept { return state_; }

    /// Get the current step counter.
    [[nodiscard]] std::uint32_t counter() const noexcept { return state_.counter; }

private:
    State state_{};
    State initial_state_{};  // For reset()

    // Buffer for partial 64-bit word extraction
    std::array<std::uint8_t, 8> buffer_{};
    std::size_t buffer_pos_ = 8; // Start empty (pos==size means empty)

    // Original key material for reset()
    std::vector<std::uint8_t> key_material_;
    std::vector<std::uint8_t> nonce_material_;
    std::vector<std::uint8_t> info_material_;
};

} // namespace eahcm

#endif // EAHCM_CIPHER_HPP
