// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
// serialization.cpp — Binary and JSON state serialization.

#include "eahcm/serialization.hpp"
#include "eahcm/exceptions.hpp"
#include "eahcm/constants.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <charconv>
#include <string>

namespace eahcm {

// ---- CRC32 (IEEE 802.3) for checksum ----
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

// ---- Binary serialization ----
// Format: [4B version LE] [36B state (9 x LE uint32)] [4B CRC32]

std::array<std::uint8_t, SERIALIZED_BINARY_SIZE>
serialize_binary(const State& s) noexcept {
    std::array<std::uint8_t, SERIALIZED_BINARY_SIZE> buf{};
    std::size_t off = 0;

    // Version
    store_le32(buf.data() + off, SERIALIZATION_VERSION); off += 4;

    // State fields in order: x, y, z, w, alpha, gamma, mu, sigma, counter
    const std::uint32_t fields[] = {
        s.x, s.y, s.z, s.w,
        s.alpha, s.gamma, s.mu, s.sigma,
        s.counter
    };
    for (auto f : fields) {
        store_le32(buf.data() + off, f); off += 4;
    }

    // CRC32 over version + state (40 bytes)
    std::uint32_t checksum = crc32(buf.data(), off);
    store_le32(buf.data() + off, checksum);

    return buf;
}

State
deserialize_binary(std::span<const std::uint8_t, SERIALIZED_BINARY_SIZE> data) {
    std::size_t off = 0;

    // Check version
    std::uint32_t ver = load_le32(data.data() + off); off += 4;
    if (ver != SERIALIZATION_VERSION) {
        throw SerializationError(
            "Binary version mismatch: expected " +
            std::to_string(SERIALIZATION_VERSION) +
            ", got " + std::to_string(ver));
    }

    // Read state fields
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

    // Verify CRC32
    std::uint32_t stored_crc = load_le32(data.data() + off);
    std::uint32_t computed_crc = crc32(data.data(), off);
    if (!secure_compare(&stored_crc, &computed_crc, 4)) {
        throw SerializationError("Binary checksum mismatch");
    }

    return s;
}

// ---- JSON serialization (minimal, dependency-free) ----

std::string serialize_json(const State& s, bool pretty) {
    // Compute CRC32 of the binary representation for the checksum field
    auto bin = serialize_binary(s);
    std::uint32_t checksum = crc32(bin.data(), 40);

    std::ostringstream os;
    const char* nl = pretty ? "\n" : "";
    const char* sp = pretty ? "  " : "";

    os << "{" << nl;
    os << sp << "\"version\": " << SERIALIZATION_VERSION << "," << nl;
    os << sp << "\"x\": " << s.x << "," << nl;
    os << sp << "\"y\": " << s.y << "," << nl;
    os << sp << "\"z\": " << s.z << "," << nl;
    os << sp << "\"w\": " << s.w << "," << nl;
    os << sp << "\"alpha\": " << s.alpha << "," << nl;
    os << sp << "\"gamma\": " << s.gamma << "," << nl;
    os << sp << "\"mu\": " << s.mu << "," << nl;
    os << sp << "\"sigma\": " << s.sigma << "," << nl;
    os << sp << "\"counter\": " << s.counter << "," << nl;
    os << sp << "\"checksum\": " << checksum << nl;
    os << "}";

    return os.str();
}

// Simple JSON parser for our known format
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

    // Verify checksum
    auto stored_checksum = parse_json_uint32(js, "checksum");
    auto bin = serialize_binary(s);
    std::uint32_t computed = crc32(bin.data(), 40);
    if (stored_checksum != computed) {
        throw SerializationError("JSON checksum mismatch");
    }

    return s;
}

} // namespace eahcm
