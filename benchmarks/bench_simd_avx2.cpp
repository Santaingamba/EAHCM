// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_simd_avx2.cpp — AVX2 isolated benchmarks

#if defined(__AVX2__)

#include "bench_simd_avx2.hpp"
#include "eahcm/detail/simd/avx2.hpp"
#include <random>
#include <array>

namespace {
template <size_t N>
std::array<eahcm::State, N> generate_random_states(std::uint32_t seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<std::uint32_t> dist;
    std::array<eahcm::State, N> states;
    for (size_t i = 0; i < N; ++i) {
        states[i] = eahcm::make_state(dist(gen), dist(gen), dist(gen), dist(gen),
                                      dist(gen), dist(gen), dist(gen), dist(gen));
    }
    return states;
}
} // namespace

void BM_SIMD_AVX2_L(benchmark::State& state) {
    __m256i v = _mm256_set1_epi32(0x12345678);
    __m256i p = _mm256_set1_epi32(0x9ABCDEF0);
    for (auto _ : state) {
        benchmark::DoNotOptimize(v);
        benchmark::DoNotOptimize(p);
        __m256i out = eahcm::detail::simd::avx2::L_vec(v, p);
        benchmark::DoNotOptimize(out);
    }
}

void BM_SIMD_AVX2_Step(benchmark::State& state) {
    auto scalar_states = generate_random_states<8>(42);
    auto vs = eahcm::detail::simd::avx2::load_states(scalar_states.data());
    
    for (auto _ : state) {
        eahcm::detail::simd::avx2::step_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 8);
}

void BM_SIMD_AVX2_Warmup(benchmark::State& state) {
    auto scalar_states = generate_random_states<8>(42);
    
    for (auto _ : state) {
        auto vs = eahcm::detail::simd::avx2::load_states(scalar_states.data());
        eahcm::detail::simd::avx2::warmup_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 8);
}

void BM_SIMD_AVX2_Extract(benchmark::State& state) {
    auto scalar_states = generate_random_states<8>(42);
    auto vs = eahcm::detail::simd::avx2::load_states(scalar_states.data());
    __m256i lo, hi;
    
    for (auto _ : state) {
        eahcm::detail::simd::avx2::extract_vec(vs, lo, hi);
        benchmark::DoNotOptimize(lo);
        benchmark::DoNotOptimize(hi);
    }
    state.SetBytesProcessed(state.iterations() * 64);
}

#endif // __AVX2__
