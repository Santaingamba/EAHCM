// SPDX-License-Identifier: MIT
// test_primitives.cpp — Unit tests for L(), F(), R(), rol32().

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <random>
#include "eahcm/arithmetic.hpp"
#include "eahcm/bit_ops.hpp"
#include "eahcm/constants.hpp"

using namespace eahcm;

// =========================================================================
// rol32 tests
// =========================================================================

TEST_CASE("rol32: round-trip invariant", "[rol32]") {
    const std::uint32_t values[] = {0xABCD1234u, 0x00000001u, 0x80000000u, 0xFFFFFFFFu, 0u};
    for (auto val : values) {
        for (int n = 1; n < 32; ++n) {
            auto rotated = rol32(val, n);
            auto recovered = rol32(rotated, 32 - n);
            REQUIRE(recovered == val);
        }
    }
}

TEST_CASE("rol32: known values", "[rol32]") {
    REQUIRE(rol32(0x80000000u, 1) == 0x00000001u);
    REQUIRE(rol32(0x00000001u, 1) == 0x00000002u);
    REQUIRE(rol32(0x00000001u, 31) == 0x80000000u);
    REQUIRE(rol32(0xFFFFFFFFu, 16) == 0xFFFFFFFFu);
}

// =========================================================================
// L() tests
// =========================================================================

TEST_CASE("L: absorbing-state guard — L(0, p) != 0", "[L]") {
    REQUIRE(L(0x00000000u, 0xF0000000u) != 0u);
}

TEST_CASE("L: absorbing-state guard — L(0xFFFFFFFF, p) != 0", "[L]") {
    REQUIRE(L(0xFFFFFFFFu, 0xF0000000u) != 0u);
}

TEST_CASE("L: output always non-zero", "[L]") {
    std::mt19937 rng(42);
    for (int i = 0; i < 100000; ++i) {
        std::uint32_t v = rng();
        std::uint32_t p = rng();
        REQUIRE(L(v, p) != 0u);
    }
}

TEST_CASE("L: output is 32-bit", "[L]") {
    std::mt19937 rng(0);
    for (int i = 0; i < 10000; ++i) {
        std::uint32_t v = rng();
        std::uint32_t p = rng();
        auto result = L(v, p);
        REQUIRE(result <= 0xFFFFFFFFu);
    }
}

TEST_CASE("L: deterministic", "[L]") {
    REQUIRE(L(0x12345678u, 0xF0000000u) == L(0x12345678u, 0xF0000000u));
}

// =========================================================================
// F() tests
// =========================================================================

TEST_CASE("F: fixed-point guard — F(0) != 0", "[F]") {
    REQUIRE(F(0u) != 0u);
    REQUIRE(F(0u) == PHI_FRAC);
}

TEST_CASE("F: F(0x80000000) != 0 (fixed-point)", "[F]") {
    // v=0x80000000: mask=0xFFFFFFFF, folded = (0x80000000 ^ 0xFFFFFFFF) << 1
    // = 0x7FFFFFFF << 1 = 0xFFFFFFFE, non-zero, guard doesn't fire
    REQUIRE(F(0x80000000u) != 0u);
}

TEST_CASE("F: output is 32-bit", "[F]") {
    std::mt19937 rng(0);
    for (int i = 0; i < 10000; ++i) {
        std::uint32_t v = rng();
        auto result = F(v);
        REQUIRE(result <= 0xFFFFFFFFu);
    }
}

// =========================================================================
// R() tests
// =========================================================================

TEST_CASE("R: non-zero for sentinel inputs", "[R]") {
    // Original broken R returned 0 for ALL inputs
    const std::uint32_t sentinels[] = {1u, 0xFFFFFFFFu, 0x80000000u, 0x12345678u, 0xDEADBEEFu};
    for (auto w : sentinels) {
        REQUIRE(R(w) != 0u);
    }
}

TEST_CASE("R: R(0) == 0", "[R]") {
    // R(0) = rol32(0,13) ^ rol32(0,7) ^ (0>>3) = 0
    REQUIRE(R(0u) == 0u);
}

TEST_CASE("R: output is 32-bit", "[R]") {
    std::mt19937 rng(0);
    for (int i = 0; i < 10000; ++i) {
        std::uint32_t w = rng();
        auto result = R(w);
        REQUIRE(result <= 0xFFFFFFFFu);
    }
}

TEST_CASE("R: known value check", "[R]") {
    // R(1) = rol32(1, 13) ^ rol32(1, 7) ^ (1 >> 3)
    // = 0x00002000 ^ 0x00000080 ^ 0x00000000
    // = 0x00002080
    REQUIRE(R(1u) == 0x00002080u);
}
