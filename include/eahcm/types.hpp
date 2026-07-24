// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// types.hpp — Strong types for the EAHCM cipher.

#ifndef EAHCM_TYPES_HPP
#define EAHCM_TYPES_HPP

#include <array>
#include <cstdint>
#include <cstddef>

#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"

namespace eahcm {

/// Internal state of the EAHCM 4D chaotic cipher.
///
/// Contains four 32-bit state variables, four chaotic parameters,
/// and a step counter. Total: 9 × 4 = 36 bytes.
///
/// This struct is used internally. The public API wraps it in the
/// Cipher class with proper RAII and secure zeroisation.
struct State {
    std::uint32_t x{};      ///< State variable x
    std::uint32_t y{};      ///< State variable y
    std::uint32_t z{};      ///< State variable z
    std::uint32_t w{};      ///< State variable w
    std::uint32_t alpha{};  ///< Chaotic parameter alpha
    std::uint32_t gamma{};  ///< Chaotic parameter gamma
    std::uint32_t mu{};     ///< Chaotic parameter mu
    std::uint32_t sigma{};  ///< Chaotic parameter sigma
    std::uint32_t counter{}; ///< Step counter (wraps at 2^32)

    /// Compare two states for exact equality.
    [[nodiscard]] constexpr bool operator==(const State& other) const noexcept = default;
    [[nodiscard]] constexpr bool operator!=(const State& other) const noexcept = default;

    /// Securely wipe all state material.
    void secure_wipe() noexcept {
        EAHCM_SECURE_ZERO(this, sizeof(State));
    }
};

static_assert(sizeof(State) == 36, "State struct must be exactly 36 bytes");

/// Endian-safe read of a little-endian uint32 from a byte buffer.
///
/// Matches Python's struct.unpack("<I", ...) exactly.
[[nodiscard]] inline constexpr std::uint32_t
load_le32(const std::uint8_t* src) noexcept {
    return static_cast<std::uint32_t>(src[0])
         | (static_cast<std::uint32_t>(src[1]) << 8)
         | (static_cast<std::uint32_t>(src[2]) << 16)
         | (static_cast<std::uint32_t>(src[3]) << 24);
}

/// Endian-safe write of a uint32 in little-endian byte order.
inline constexpr void
store_le32(std::uint8_t* dst, std::uint32_t val) noexcept {
    dst[0] = static_cast<std::uint8_t>(val);
    dst[1] = static_cast<std::uint8_t>(val >> 8);
    dst[2] = static_cast<std::uint8_t>(val >> 16);
    dst[3] = static_cast<std::uint8_t>(val >> 24);
}

/// Endian-safe read of a big-endian uint32 from a byte buffer.
[[nodiscard]] inline constexpr std::uint32_t
load_be32(const std::uint8_t* src) noexcept {
    return (static_cast<std::uint32_t>(src[0]) << 24)
         | (static_cast<std::uint32_t>(src[1]) << 16)
         | (static_cast<std::uint32_t>(src[2]) << 8)
         |  static_cast<std::uint32_t>(src[3]);
}

/// Endian-safe write of a uint32 in big-endian byte order.
inline constexpr void
store_be32(std::uint8_t* dst, std::uint32_t val) noexcept {
    dst[0] = static_cast<std::uint8_t>(val >> 24);
    dst[1] = static_cast<std::uint8_t>(val >> 16);
    dst[2] = static_cast<std::uint8_t>(val >> 8);
    dst[3] = static_cast<std::uint8_t>(val);
}

/// Constant-time comparison for cryptographic use.
/// Returns true iff the two buffers are byte-identical.
/// Never short-circuits — always examines all bytes.
[[nodiscard]] inline bool
secure_compare(const void* a, const void* b, std::size_t len) noexcept {
    const auto* pa = static_cast<const volatile std::uint8_t*>(a);
    const auto* pb = static_cast<const volatile std::uint8_t*>(b);
    volatile std::uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<std::uint8_t>(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

} // namespace eahcm

#endif // EAHCM_TYPES_HPP
