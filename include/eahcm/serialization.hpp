// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// serialization.hpp — State serialization (binary and JSON).

#ifndef EAHCM_SERIALIZATION_HPP
#define EAHCM_SERIALIZATION_HPP

#include <array>
#include <cstdint>
#include <string>
#include <span>

#include "eahcm/config.hpp"
#include "eahcm/types.hpp"
#include "eahcm/version.hpp"

namespace eahcm {

/// Binary serialization format:
///   [4 bytes] version (LE)
///   [36 bytes] state (9 × LE uint32)
///   [4 bytes] CRC32 checksum
///   Total: 44 bytes
inline constexpr std::size_t SERIALIZED_BINARY_SIZE = 44;

/// Serialize a State to a portable binary format.
///
/// Format is little-endian, version-tagged, and checksumed.
/// Safe across platforms and endianness.
///
/// @param s  The state to serialize.
/// @return   44-byte binary representation.
EAHCM_API [[nodiscard]] std::array<std::uint8_t, SERIALIZED_BINARY_SIZE>
serialize_binary(const State& s) noexcept;

/// Deserialize a State from the portable binary format.
///
/// @param data  Exactly 44 bytes of serialized state.
/// @return      The deserialized state.
/// @throws SerializationError on version mismatch or checksum failure.
EAHCM_API [[nodiscard]] State
deserialize_binary(std::span<const std::uint8_t, SERIALIZED_BINARY_SIZE> data);

/// Serialize a State to a JSON string.
///
/// All integers are stored as decimal for unambiguous numeric comparison.
/// Includes version field and checksum.
///
/// @param s      The state to serialize.
/// @param pretty If true, format with indentation.
/// @return       JSON string representation.
EAHCM_API [[nodiscard]] std::string
serialize_json(const State& s, bool pretty = true);

/// Deserialize a State from a JSON string.
///
/// @param json  The JSON string.
/// @return      The deserialized state.
/// @throws SerializationError on parse error, version mismatch, or bad checksum.
EAHCM_API [[nodiscard]] State
deserialize_json(std::string_view json);

} // namespace eahcm

#endif // EAHCM_SERIALIZATION_HPP
