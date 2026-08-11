// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_simd_neon.cpp — NEON isolated benchmarks

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

#include "bench_simd_neon.hpp"
#include "eahcm/detail/simd/neon.hpp"
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

void BM_SIMD_NEON_Step(benchmark::State& state) {
    auto scalar_states = generate_random_states<4>(42);
    auto vs = eahcm::detail::simd::neon::load_states(scalar_states.data());
    
    for (auto _ : state) {
        eahcm::detail::simd::neon::step_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 4);
}

void BM_SIMD_NEON_Warmup(benchmark::State& state) {
    auto scalar_states = generate_random_states<4>(42);
    
    for (auto _ : state) {
        auto vs = eahcm::detail::simd::neon::load_states(scalar_states.data());
        eahcm::detail::simd::neon::warmup_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 4);
}

void BM_SIMD_NEON_Extract(benchmark::State& state) {
    auto scalar_states = generate_random_states<4>(42);
    auto vs = eahcm::detail::simd::neon::load_states(scalar_states.data());
    uint32x4_t lo, hi;
    
    for (auto _ : state) {
        eahcm::detail::simd::neon::extract_vec(vs, lo, hi);
        benchmark::DoNotOptimize(lo);
        benchmark::DoNotOptimize(hi);
    }
    state.SetBytesProcessed(state.iterations() * 32);
}

#endif // __ARM_NEON
