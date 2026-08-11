// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_simd.cpp — Bit-exact differential testing of SIMD backends against scalar.

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "eahcm/arithmetic.hpp"
#include "eahcm/state.hpp"
#include "eahcm/detail/simd/vector_state.hpp"

#if defined(__AVX2__)
#include "eahcm/detail/simd/avx2.hpp"
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include "eahcm/detail/simd/neon.hpp"
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

#if defined(__AVX2__)

TEST_CASE("AVX2 L() exact equivalence", "[simd][avx2]") {
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

    __m256i vec_v = _mm256_load_si256((__m256i*)v);
    __m256i vec_p = _mm256_load_si256((__m256i*)p);
    __m256i vec_out = detail::simd::avx2::L_vec(vec_v, vec_p);
    _mm256_store_si256((__m256i*)out, vec_out);

    for (int i = 0; i < 8; ++i) {
        REQUIRE(out[i] == eahcm::L(v[i], p[i]));
    }
}

TEST_CASE("AVX2 F() exact equivalence", "[simd][avx2]") {
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

    __m256i vec_v = _mm256_load_si256((__m256i*)v);
    __m256i vec_out = detail::simd::avx2::F_vec(vec_v);
    _mm256_store_si256((__m256i*)out, vec_out);

    for (int i = 0; i < 8; ++i) {
        REQUIRE(out[i] == eahcm::F(v[i]));
    }
}

TEST_CASE("AVX2 R() exact equivalence", "[simd][avx2]") {
    std::mt19937 gen(101);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(32) std::uint32_t w[8], out[8];
    for (int i = 0; i < 8; ++i) {
        w[i] = dist(gen);
    }
    
    __m256i vec_w = _mm256_load_si256((__m256i*)w);
    __m256i vec_out = detail::simd::avx2::R_vec(vec_w);
    _mm256_store_si256((__m256i*)out, vec_out);

    for (int i = 0; i < 8; ++i) {
        REQUIRE(out[i] == eahcm::R(w[i]));
    }
}

TEST_CASE("AVX2 State Evolution exact equivalence", "[simd][avx2]") {
    auto seeds = {1u, 42u, 1337u, 0xDEADBEEFu};
    for (auto seed : seeds) {
        auto scalar_states = generate_random_states<8>(seed);
        
        // Edge cases for counter alignment (drift boundaries and wraps)
        scalar_states[0].counter = DRIFT_INTERVAL - 1;
        scalar_states[1].counter = 0;
        scalar_states[2].counter = DRIFT_INTERVAL;
        scalar_states[3].counter = 0xFFFFFFFE; // Wraparound approaching
        scalar_states[4].counter = 0xFFFFFFFF; // Wraparound
        
        auto vec_state = detail::simd::avx2::load_states(scalar_states.data());
        std::array<State, 8> out_states;
        
        std::vector<int> checkpoints = {1, 64, 65, 128, 256};
        int current_step = 0;

        for (int target : checkpoints) {
            while (current_step < target) {
                for (int i = 0; i < 8; ++i) eahcm::step(scalar_states[i]);
                detail::simd::avx2::step_vec(vec_state);
                current_step++;
            }
            detail::simd::avx2::store_states(out_states.data(), vec_state);
            require_states_match(scalar_states, out_states, seed, current_step);
        }
        
        // Test extraction
        __m256i out_lo_4, out_hi_4;
        detail::simd::avx2::extract_vec(vec_state, out_lo_4, out_hi_4);
        alignas(32) std::uint64_t v_lo[4], v_hi[4];
        _mm256_store_si256((__m256i*)v_lo, out_lo_4);
        _mm256_store_si256((__m256i*)v_hi, out_hi_4);
        
        std::uint64_t vec_extracts[8] = {
            v_lo[0], v_lo[1], v_lo[2], v_lo[3],
            v_hi[0], v_hi[1], v_hi[2], v_hi[3]
        };
        for (int i = 0; i < 8; ++i) {
            REQUIRE(vec_extracts[i] == eahcm::extract(scalar_states[i]));
        }
    }
}

#endif // __AVX2__

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

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

    uint32x4_t vec_v = vld1q_u32(v);
    uint32x4_t vec_p = vld1q_u32(p);
    uint32x4_t vec_out = detail::simd::neon::L_vec(vec_v, vec_p);
    vst1q_u32(out, vec_out);

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

    uint32x4_t vec_v = vld1q_u32(v);
    uint32x4_t vec_out = detail::simd::neon::F_vec(vec_v);
    vst1q_u32(out, vec_out);

    for (int i = 0; i < 4; ++i) REQUIRE(out[i] == eahcm::F(v[i]));
}

TEST_CASE("NEON R() exact equivalence", "[simd][neon]") {
    std::mt19937 gen(101);
    std::uniform_int_distribution<std::uint32_t> dist;

    alignas(16) std::uint32_t w[4], out[4];
    for (int i = 0; i < 4; ++i) {
        w[i] = dist(gen);
    }
    
    uint32x4_t vec_w = vld1q_u32(w);
    uint32x4_t vec_out = detail::simd::neon::R_vec(vec_w);
    vst1q_u32(out, vec_out);

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
        
        auto vec_state = detail::simd::neon::load_states(scalar_states.data());
        std::array<State, 4> out_states;
        
        std::vector<int> checkpoints = {1, 64, 65, 128, 256};
        int current_step = 0;

        for (int target : checkpoints) {
            while (current_step < target) {
                for (int i = 0; i < 4; ++i) eahcm::step(scalar_states[i]);
                detail::simd::neon::step_vec(vec_state);
                current_step++;
            }
            detail::simd::neon::store_states(out_states.data(), vec_state);
            require_states_match(scalar_states, out_states, seed, current_step);
        }
        
        // Test extraction
        uint32x4_t out_lo_2, out_hi_2;
        detail::simd::neon::extract_vec(vec_state, out_lo_2, out_hi_2);
        alignas(16) std::uint64_t v_lo[2], v_hi[2];
        vst1q_u64((uint64_t*)v_lo, vreinterpretq_u64_u32(out_lo_2));
        vst1q_u64((uint64_t*)v_hi, vreinterpretq_u64_u32(out_hi_2));
        
        std::uint64_t vec_extracts[4] = {
            v_lo[0], v_lo[1],
            v_hi[0], v_hi[1]
        };
        for (int i = 0; i < 4; ++i) {
            REQUIRE(vec_extracts[i] == eahcm::extract(scalar_states[i]));
        }
    }
}

#endif // __ARM_NEON
