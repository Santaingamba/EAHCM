// SPDX-License-Identifier: MIT
// test_serialization.cpp — Tests for binary and JSON serialization.

#include <catch2/catch_test_macros.hpp>
#include "eahcm/serialization.hpp"
#include "eahcm/state.hpp"
#include "eahcm/exceptions.hpp"

using namespace eahcm;

TEST_CASE("Binary serialization: round-trip", "[serialization]") {
    State s = make_state(
        0x12345678u, 0x9ABCDEF0u, 0x13572468u, 0xACEBDFACu,
        0xF0000000u, 0xF1000000u, 0xF2000000u, 0xF3000000u
    );
    // Advance a few steps to get non-trivial state
    for (int i = 0; i < 100; ++i) step(s);

    auto bin = serialize_binary(s);
    auto restored = deserialize_binary(bin);
    REQUIRE(s == restored);
}

TEST_CASE("Binary serialization: checksum detects corruption", "[serialization]") {
    State s = make_state(
        0xDEADBEEFu, 0x13371337u, 0xCAFEBABEu, 0xBAADF00Du,
        0xF5000000u, 0xF6000000u, 0xF7000000u, 0xF8000000u
    );

    auto bin = serialize_binary(s);
    bin[10] ^= 0x01; // Corrupt one byte
    REQUIRE_THROWS_AS(deserialize_binary(bin), SerializationError);
}

TEST_CASE("JSON serialization: round-trip", "[serialization]") {
    State s = make_state(
        0x12345678u, 0x9ABCDEF0u, 0x13572468u, 0xACEBDFACu,
        0xF0000000u, 0xF1000000u, 0xF2000000u, 0xF3000000u
    );
    for (int i = 0; i < 50; ++i) step(s);

    auto json_str = serialize_json(s, true);
    auto restored = deserialize_json(json_str);
    REQUIRE(s == restored);
}

TEST_CASE("JSON serialization: compact format", "[serialization]") {
    State s{};
    s.x = 42; s.y = 43; s.z = 44; s.w = 45;
    s.alpha = PARAM_FLOOR; s.gamma = PARAM_FLOOR;
    s.mu = PARAM_FLOOR; s.sigma = PARAM_FLOOR;
    s.counter = 0;

    auto json_str = serialize_json(s, false);
    REQUIRE(json_str.find('\n') == std::string::npos);
}
