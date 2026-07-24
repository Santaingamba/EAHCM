// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
// cipher.cpp — High-level Cipher API implementation.

#include "eahcm/cipher.hpp"
#include <algorithm>
#include <cstring>
#include <utility>

namespace eahcm {

Cipher::Cipher(std::span<const std::uint8_t> key,
               std::span<const std::uint8_t> nonce,
               std::span<const std::uint8_t> info) {
    if (key.empty()) throw KeyError("key must not be empty");
    key_material_.assign(key.begin(), key.end());
    nonce_material_.assign(nonce.begin(), nonce.end());
    info_material_.assign(info.begin(), info.end());
    state_ = derive_state(key, nonce, {}, info);
    initial_state_ = state_;
}

Cipher::~Cipher() {
    state_.secure_wipe();
    initial_state_.secure_wipe();
    EAHCM_SECURE_ZERO(buffer_.data(), buffer_.size());
    if (!key_material_.empty())
        EAHCM_SECURE_ZERO(key_material_.data(), key_material_.size());
    if (!nonce_material_.empty())
        EAHCM_SECURE_ZERO(nonce_material_.data(), nonce_material_.size());
}

Cipher::Cipher(Cipher&& other) noexcept
    : state_(other.state_), initial_state_(other.initial_state_),
      buffer_(other.buffer_), buffer_pos_(other.buffer_pos_),
      key_material_(std::move(other.key_material_)),
      nonce_material_(std::move(other.nonce_material_)),
      info_material_(std::move(other.info_material_)) {
    other.state_.secure_wipe();
    other.initial_state_.secure_wipe();
    EAHCM_SECURE_ZERO(other.buffer_.data(), other.buffer_.size());
    other.buffer_pos_ = 8;
}

Cipher& Cipher::operator=(Cipher&& other) noexcept {
    if (this != &other) {
        state_.secure_wipe();
        initial_state_.secure_wipe();
        EAHCM_SECURE_ZERO(buffer_.data(), buffer_.size());
        state_ = other.state_; initial_state_ = other.initial_state_;
        buffer_ = other.buffer_; buffer_pos_ = other.buffer_pos_;
        key_material_ = std::move(other.key_material_);
        nonce_material_ = std::move(other.nonce_material_);
        info_material_ = std::move(other.info_material_);
        other.state_.secure_wipe();
        other.initial_state_.secure_wipe();
        EAHCM_SECURE_ZERO(other.buffer_.data(), other.buffer_.size());
        other.buffer_pos_ = 8;
    }
    return *this;
}

std::uint64_t Cipher::next() {
    step(state_);
    return extract(state_);
}

// ---- Keystream generation: partial-word buffering strategy ----
//
// The chaotic core produces 64-bit words (8 bytes) at a time via next().
// Users may request an arbitrary number of bytes via generate(). To bridge
// this mismatch, we use a 3-phase approach:
//
//   Phase 1: Drain leftover bytes from the previous call's partial word
//            (buffer_pos_ < 8 means there are leftover bytes).
//   Phase 2: Fill 8-byte-aligned chunks directly from next() — no buffering
//            overhead, maximum throughput.
//   Phase 3: If trailing bytes remain (output size not a multiple of 8),
//            generate one more 64-bit word, serve the needed bytes, and
//            save the remainder in buffer_ for the next call.
//
// buffer_pos_ == 8 means the buffer is empty (fully consumed).

void Cipher::generate(std::span<std::uint8_t> output) {
    std::size_t pos = 0;
    while (pos < output.size() && buffer_pos_ < 8)
        output[pos++] = buffer_[buffer_pos_++];
    while (pos + 8 <= output.size()) {
        const std::uint64_t word = next();
        for (int i = 0; i < 8; ++i)
            output[pos + i] = static_cast<std::uint8_t>(word >> (i * 8));
        pos += 8;
    }
    if (pos < output.size()) {
        const std::uint64_t word = next();
        for (int i = 0; i < 8; ++i)
            buffer_[i] = static_cast<std::uint8_t>(word >> (i * 8));
        buffer_pos_ = 0;
        while (pos < output.size())
            output[pos++] = buffer_[buffer_pos_++];
    }
}

std::vector<std::uint8_t> Cipher::generate(std::size_t count) {
    std::vector<std::uint8_t> result(count);
    generate(result);
    return result;
}

void Cipher::reset() {
    state_ = initial_state_;
    buffer_pos_ = 8;
    EAHCM_SECURE_ZERO(buffer_.data(), buffer_.size());
}

void Cipher::reseed(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> nonce,
                    std::span<const std::uint8_t> info) {
    if (key.empty()) throw KeyError("key must not be empty");
    state_.secure_wipe(); initial_state_.secure_wipe();
    EAHCM_SECURE_ZERO(buffer_.data(), buffer_.size());
    if (!key_material_.empty())
        EAHCM_SECURE_ZERO(key_material_.data(), key_material_.size());
    key_material_.assign(key.begin(), key.end());
    nonce_material_.assign(nonce.begin(), nonce.end());
    info_material_.assign(info.begin(), info.end());
    state_ = derive_state(key, nonce, {}, info);
    initial_state_ = state_;
    buffer_pos_ = 8;
}

std::array<std::uint8_t, SERIALIZED_BINARY_SIZE>
Cipher::export_state() const { return serialize_binary(state_); }

void Cipher::import_state(
    std::span<const std::uint8_t, SERIALIZED_BINARY_SIZE> data) {
    state_ = deserialize_binary(data);
    buffer_pos_ = 8;
    EAHCM_SECURE_ZERO(buffer_.data(), buffer_.size());
}

std::string Cipher::export_state_json(bool pretty) const {
    return serialize_json(state_, pretty);
}

void Cipher::import_state_json(std::string_view json) {
    state_ = deserialize_json(json);
    buffer_pos_ = 8;
    EAHCM_SECURE_ZERO(buffer_.data(), buffer_.size());
}

} // namespace eahcm
