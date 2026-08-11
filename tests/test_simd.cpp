// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_simd.cpp — Bit-exact differential testing of SIMD backends against scalar.

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "eahcm/arithmetic.hpp"
#include "eahcm/state.hpp"
#include "eahcm/detail/simd/detect.hpp"

#if defined(__AVX2__) || defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#define EAHCM_HAS_AVX2_TESTS
#include "test_simd_avx2.hpp"
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON) || defined(__ARM_NEON__)
#define EAHCM_HAS_NEON_TESTS
#include "test_simd_neon.hpp"
#endif

#include <vector>
#include <random>

using namespace eahcm;

// Generates an array of N random scalar states
template <size_t N>
std::array<State, N> generate_random_states(std::uint32_t seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<std::uint32_t> dist;
    std::array<State, N> states;
    for (size_t i = 0; i < N; ++i) {
        states[i] = make_state(dist(gen), dist(gen), dist(gen), dist(gen),
                               dist(gen), dist(gen), dist(gen), dist(gen));
    }
    return states;
}

// Compare scalar states with SIMD states for exact equivalence
template <size_t N>
void require_states_match(const std::array<State, N>& expected, const std::array<State, N>& actual, std::uint32_t seed, int step_num) {
    for (size_t i = 0; i < N; ++i) {
        INFO("Seed: " << seed << " Step: " << step_num << " Lane: " << i);
        INFO("Scalar counter: " << expected[i].counter << " SIMD counter: " << actual[i].counter);
        REQUIRE(actual[i].x == expected[i].x);
        REQUIRE(actual[i].y == expected[i].y);
        REQUIRE(actual[i].z == expected[i].z);
        REQUIRE(actual[i].w == expected[i].w);
        REQUIRE(actual[i].alpha == expected[i].alpha);
        REQUIRE(actual[i].gamma == expected[i].gamma);
        REQUIRE(actual[i].mu == expected[i].mu);
        REQUIRE(actual[i].sigma == expected[i].sigma);
        REQUIRE(actual[i].counter == expected[i].counter);
    }
}

#if defined(EAHCM_HAS_AVX2_TESTS)

TEST_CASE("AVX2 L() exact equivalence", "[simd][avx2]") {
    if (!eahcm::detail::simd::cpu_supports_avx2()) SKIP("CPU does not support AVX2");
    std::mt19937 gen(1337);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(32) std::uint32_t v[8], p[8], out[8];
    for (int i = 0; i < 8; ++i) {
        v[i] = dist(gen);
        p[i] = dist(gen);
    }
    // Edge cases
    v[0] = 0x00000000;
    v[1] = 0xFFFFFFFF;
    v[2] = 0x80000000;
    p[3] = 0x00000000;
    p[4] = 0xFFFFFFFF;

    avx2_L_vec_compute(v, p, out);

    for (int i = 0; i < 8; ++i) {
        REQUIRE(out[i] == eahcm::L(v[i], p[i]));
    }
}

TEST_CASE("AVX2 F() exact equivalence", "[simd][avx2]") {
    if (!eahcm::detail::simd::cpu_supports_avx2()) SKIP("CPU does not support AVX2");
    std::mt19937 gen(42);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(32) std::uint32_t v[8], out[8];
    for (int i = 0; i < 8; ++i) {
        v[i] = dist(gen);
    }
    // Fixed point guards
    v[0] = 0x00000000;
    v[1] = 0x80000000;
    v[2] = 0xFFFFFFFF;

    avx2_F_vec_compute(v, out);

    for (int i = 0; i < 8; ++i) {
        REQUIRE(out[i] == eahcm::F(v[i]));
    }
}

TEST_CASE("AVX2 R() exact equivalence", "[simd][avx2]") {
    if (!eahcm::detail::simd::cpu_supports_avx2()) SKIP("CPU does not support AVX2");
    std::mt19937 gen(101);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(32) std::uint32_t w[8], out[8];
    for (int i = 0; i < 8; ++i) {
        w[i] = dist(gen);
    }
    
    avx2_R_vec_compute(w, out);

    for (int i = 0; i < 8; ++i) {
        REQUIRE(out[i] == eahcm::R(w[i]));
    }
}

TEST_CASE("AVX2 State Evolution exact equivalence", "[simd][avx2]") {
    if (!eahcm::detail::simd::cpu_supports_avx2()) SKIP("CPU does not support AVX2");
    auto seeds = {1u, 42u, 1337u, 0xDEADBEEFu};
    for (auto seed : seeds) {
        auto scalar_states = generate_random_states<8>(seed);
        
        // Edge cases for counter alignment (drift boundaries and wraps)
        scalar_states[0].counter = DRIFT_INTERVAL - 1;
        scalar_states[1].counter = 0;
        scalar_states[2].counter = DRIFT_INTERVAL;
        scalar_states[3].counter = 0xFFFFFFFE; // Wraparound approaching
        scalar_states[4].counter = 0xFFFFFFFF; // Wraparound
        
        std::array<State, 8> out_states;
        std::vector<int> checkpoints = {1, 64, 65, 128, 256};
        int current_step = 0;

        for (int target : checkpoints) {
            int step_diff = target - current_step;
            
            // Advance SIMD state
            avx2_step_vec_compute(scalar_states.data(), out_states.data(), step_diff);
            
            // Advance scalar states manually
            for (int i = 0; i < step_diff; ++i) {
                for (int s = 0; s < 8; ++s) eahcm::step(scalar_states[s]);
            }
            
            current_step = target;
            require_states_match(scalar_states, out_states, seed, current_step);
            
            // Re-sync states for next chunk
            scalar_states = out_states;
        }
        
        // Test extraction
        std::uint64_t vec_extracts[8];
        avx2_extract_vec_compute(scalar_states.data(), vec_extracts);
        
        for (int i = 0; i < 8; ++i) {
            REQUIRE(vec_extracts[i] == eahcm::extract(scalar_states[i]));
        }
    }
}

#endif // EAHCM_HAS_AVX2_TESTS


#if defined(EAHCM_HAS_NEON_TESTS)

TEST_CASE("NEON L() exact equivalence", "[simd][neon]") {
    std::mt19937 gen(1337);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(16) std::uint32_t v[4], p[4], out[4];
    for (int i = 0; i < 4; ++i) {
        v[i] = dist(gen);
        p[i] = dist(gen);
    }
    v[0] = 0x00000000;
    v[1] = 0xFFFFFFFF;
    v[2] = 0x80000000;
    p[3] = 0x00000000;

    neon_L_vec_compute(v, p, out);

    for (int i = 0; i < 4; ++i) REQUIRE(out[i] == eahcm::L(v[i], p[i]));
}

TEST_CASE("NEON F() exact equivalence", "[simd][neon]") {
    std::mt19937 gen(42);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(16) std::uint32_t v[4], out[4];
    for (int i = 0; i < 4; ++i) {
        v[i] = dist(gen);
    }
    v[0] = 0x00000000;
    v[1] = 0x80000000;
    v[2] = 0xFFFFFFFF;

    neon_F_vec_compute(v, out);

    for (int i = 0; i < 4; ++i) REQUIRE(out[i] == eahcm::F(v[i]));
}

TEST_CASE("NEON R() exact equivalence", "[simd][neon]") {
    std::mt19937 gen(101);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(16) std::uint32_t w[4], out[4];
    for (int i = 0; i < 4; ++i) {
        w[i] = dist(gen);
    }
    
    neon_R_vec_compute(w, out);

    for (int i = 0; i < 4; ++i) REQUIRE(out[i] == eahcm::R(w[i]));
}

TEST_CASE("NEON State Evolution exact equivalence", "[simd][neon]") {
    auto seeds = {1u, 42u, 1337u, 0xDEADBEEFu};
    for (auto seed : seeds) {
        auto scalar_states = generate_random_states<4>(seed);
        
        scalar_states[0].counter = DRIFT_INTERVAL - 1;
        scalar_states[1].counter = 0;
        scalar_states[2].counter = 0xFFFFFFFE; // Wraparound
        scalar_states[3].counter = 0xFFFFFFFF; // Wraparound
        
        std::array<State, 4> out_states;
        std::vector<int> checkpoints = {1, 64, 65, 128, 256};
        int current_step = 0;

        for (int target : checkpoints) {
            int step_diff = target - current_step;
            neon_step_vec_compute(scalar_states.data(), out_states.data(), step_diff);
            
            for (int i = 0; i < step_diff; ++i) {
                for (int s = 0; s < 4; ++s) eahcm::step(scalar_states[s]);
            }
            
            current_step = target;
            require_states_match(scalar_states, out_states, seed, current_step);
            
            scalar_states = out_states;
        }
        
        // Test extraction
        std::uint64_t vec_extracts[4];
        neon_extract_vec_compute(scalar_states.data(), vec_extracts);
        
        for (int i = 0; i < 4; ++i) {
            REQUIRE(vec_extracts[i] == eahcm::extract(scalar_states[i]));
        }
    }
}

#endif // EAHCM_HAS_NEON_TESTS
