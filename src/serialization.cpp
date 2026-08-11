// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// serialization.cpp — Binary and JSON state serialization for EAHCM.
//
// Provides two serialization formats for eahcm::State:
//
//   Binary (serialize_binary / deserialize_binary)
//   ───────────────────────────────────────────────
//   A compact, version-tagged, checksummed binary blob.
//   Format: [4B version LE] [36B state: 9×uint32 LE] [4B CRC32] = 44 bytes
//   (SERIALIZED_BINARY_SIZE).
//   - All fields are little-endian for portability.
//   - CRC32 (IEEE 802.3 polynomial) covers the first 40 bytes (version +
//     state fields).
//   - Deserialization verifies version and CRC32 before returning.
//
//   JSON (serialize_json / deserialize_json)
//   ─────────────────────────────────────────
//   A human-readable, dependency-free JSON string.
//   - All 9 state fields are stored as unsigned decimal integers.
//   - The "checksum" field is the CRC32 of the binary representation of
//     the state, NOT a re-serialization of the JSON.
//   - A minimal hand-rolled parser is used to avoid any external JSON
//     dependency in the library itself (nlohmann/json is a test-only dep).
//
// Security note: deserialization of the binary format uses secure_compare()
// (constant-time) for the CRC32 comparison to avoid timing side-channels.

#include "eahcm/serialization.hpp"
#include "eahcm/exceptions.hpp"
#include "eahcm/constants.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <charconv>
#include <string>

namespace eahcm {

// =========================================================================
// CRC32 (IEEE 802.3 / PKZIP polynomial 0xEDB88320)
// =========================================================================
//
// Used as an integrity checksum for both binary and JSON formats.
// This is NOT a cryptographic hash — it detects accidental corruption only.
// Forgery resistance is provided by the HKDF key derivation, not this CRC.

static std::uint32_t crc32(const std::uint8_t* data, std::size_t len) noexcept {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
        }
    }
    return ~crc;
}

// =========================================================================
// Binary serialization
// =========================================================================

std::array<std::uint8_t, SERIALIZED_BINARY_SIZE>
serialize_binary(const State& s) noexcept {
    std::array<std::uint8_t, SERIALIZED_BINARY_SIZE> buf{};
    std::size_t off = 0;

    // Version tag (4 bytes, LE)
    store_le32(buf.data() + off, SERIALIZATION_VERSION); off += 4;

    // State fields in canonical order: x, y, z, w, alpha, gamma, mu, sigma, counter
    const std::uint32_t fields[] = {
        s.x, s.y, s.z, s.w,
        s.alpha, s.gamma, s.mu, s.sigma,
        s.counter
    };
    for (auto f : fields) {
        store_le32(buf.data() + off, f); off += 4;
    }

    // CRC32 over the first 40 bytes (version + 9 state fields)
    std::uint32_t checksum = crc32(buf.data(), off);
    store_le32(buf.data() + off, checksum);

    return buf;
}

State
deserialize_binary(std::span<const std::uint8_t, SERIALIZED_BINARY_SIZE> data) {
    std::size_t off = 0;

    // Version check
    std::uint32_t ver = load_le32(data.data() + off); off += 4;
    if (ver != SERIALIZATION_VERSION) {
        throw SerializationError(
            "Binary version mismatch: expected " +
            std::to_string(SERIALIZATION_VERSION) +
            ", got " + std::to_string(ver));
    }

    // Read state fields in canonical order
    State s;
    s.x       = load_le32(data.data() + off); off += 4;
    s.y       = load_le32(data.data() + off); off += 4;
    s.z       = load_le32(data.data() + off); off += 4;
    s.w       = load_le32(data.data() + off); off += 4;
    s.alpha   = load_le32(data.data() + off); off += 4;
    s.gamma   = load_le32(data.data() + off); off += 4;
    s.mu      = load_le32(data.data() + off); off += 4;
    s.sigma   = load_le32(data.data() + off); off += 4;
    s.counter = load_le32(data.data() + off); off += 4;

    // CRC32 verification — constant-time comparison (secure_compare)
    std::uint32_t stored_crc = load_le32(data.data() + off);
    std::uint32_t computed_crc = crc32(data.data(), off);
    if (!secure_compare(&stored_crc, &computed_crc, 4)) {
        throw SerializationError("Binary checksum mismatch");
    }

    return s;
}

// =========================================================================
// JSON serialization (minimal, dependency-free)
// =========================================================================

std::string serialize_json(const State& s, bool pretty) {
    // CRC32 is computed over the binary form of the state so that the
    // checksum field is consistent with deserialize_binary().
    auto bin = serialize_binary(s);
    std::uint32_t checksum = crc32(bin.data(), 40);

    std::ostringstream os;
    const char* nl = pretty ? "\n" : "";
    const char* sp = pretty ? "  " : "";

    os << "{" << nl;
    os << sp << "\"version\": " << SERIALIZATION_VERSION << "," << nl;
    os << sp << "\"x\": "       << s.x       << "," << nl;
    os << sp << "\"y\": "       << s.y       << "," << nl;
    os << sp << "\"z\": "       << s.z       << "," << nl;
    os << sp << "\"w\": "       << s.w       << "," << nl;
    os << sp << "\"alpha\": "   << s.alpha   << "," << nl;
    os << sp << "\"gamma\": "   << s.gamma   << "," << nl;
    os << sp << "\"mu\": "      << s.mu      << "," << nl;
    os << sp << "\"sigma\": "   << s.sigma   << "," << nl;
    os << sp << "\"counter\": " << s.counter << "," << nl;
    os << sp << "\"checksum\": " << checksum << nl;
    os << "}";

    return os.str();
}

// ---- Minimal JSON field parser ----
// Finds the first occurrence of "key" in the JSON string, skips whitespace
// after the colon, and parses the decimal uint32 value.
static std::uint32_t parse_json_uint32(const std::string& json, const std::string& key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) {
        throw SerializationError("JSON missing field: " + key);
    }
    pos = json.find(':', pos);
    if (pos == std::string::npos) throw SerializationError("JSON parse error");
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        pos++;
    std::uint32_t value = 0;
    auto [ptr, ec] = std::from_chars(json.data() + pos, json.data() + json.size(), value);
    if (ec != std::errc{}) {
        throw SerializationError("JSON parse error for field: " + key);
    }
    return value;
}

State deserialize_json(std::string_view json) {
    std::string js(json);

    auto ver = parse_json_uint32(js, "version");
    if (ver != SERIALIZATION_VERSION) {
        throw SerializationError("JSON version mismatch");
    }

    State s;
    s.x       = parse_json_uint32(js, "x");
    s.y       = parse_json_uint32(js, "y");
    s.z       = parse_json_uint32(js, "z");
    s.w       = parse_json_uint32(js, "w");
    s.alpha   = parse_json_uint32(js, "alpha");
    s.gamma   = parse_json_uint32(js, "gamma");
    s.mu      = parse_json_uint32(js, "mu");
    s.sigma   = parse_json_uint32(js, "sigma");
    s.counter = parse_json_uint32(js, "counter");

    // Verify checksum against binary representation
    auto stored_checksum = parse_json_uint32(js, "checksum");
    auto bin = serialize_binary(s);
    std::uint32_t computed = crc32(bin.data(), 40);
    if (stored_checksum != computed) {
        throw SerializationError("JSON checksum mismatch");
    }

    return s;
}

} // namespace eahcm
