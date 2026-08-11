// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_simd.cpp — Benchmarks for SIMD batched processing.

#include <benchmark/benchmark.h>
#include <array>
#include <random>

#include "eahcm/detail/simd/vector_state.hpp"

#if defined(__AVX2__)
#include "eahcm/detail/simd/avx2.hpp"
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include "eahcm/detail/simd/neon.hpp"
#endif

using namespace eahcm;

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

#if defined(__AVX2__)

#if defined(_MSC_VER)
#include <intrin.h>
#endif

static bool cpu_supports_avx2() {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 5)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") > 0;
#else
    return true;
#endif
}

static void BM_SIMD_AVX2_L(benchmark::State& state) {
    if (!cpu_supports_avx2()) {
        state.SkipWithError("CPU does not support AVX2");
        return;
    }
    __m256i v = _mm256_set1_epi32(0x12345678);
    __m256i p = _mm256_set1_epi32(0x9ABCDEF0);
    for (auto _ : state) {
        benchmark::DoNotOptimize(v);
        benchmark::DoNotOptimize(p);
        __m256i out = detail::simd::avx2::L_vec(v, p);
        benchmark::DoNotOptimize(out);
    }
}
BENCHMARK(BM_SIMD_AVX2_L);

static void BM_SIMD_AVX2_Step(benchmark::State& state) {
    if (!cpu_supports_avx2()) {
        state.SkipWithError("CPU does not support AVX2");
        return;
    }
    auto scalar_states = generate_random_states<8>(42);
    auto vs = detail::simd::avx2::load_states(scalar_states.data());
    
    for (auto _ : state) {
        detail::simd::avx2::step_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    // AVX2 processes 8 states per step
    state.SetItemsProcessed(state.iterations() * 8);
}
BENCHMARK(BM_SIMD_AVX2_Step);

static void BM_SIMD_AVX2_Warmup(benchmark::State& state) {
    auto scalar_states = generate_random_states<8>(42);
    
    for (auto _ : state) {
        auto vs = detail::simd::avx2::load_states(scalar_states.data());
        detail::simd::avx2::warmup_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 8);
}
BENCHMARK(BM_SIMD_AVX2_Warmup);

static void BM_SIMD_AVX2_Extract(benchmark::State& state) {
    auto scalar_states = generate_random_states<8>(42);
    auto vs = detail::simd::avx2::load_states(scalar_states.data());
    __m256i lo, hi;
    
    for (auto _ : state) {
        detail::simd::avx2::extract_vec(vs, lo, hi);
        benchmark::DoNotOptimize(lo);
        benchmark::DoNotOptimize(hi);
    }
    // Extracts 8x 64-bit keystreams per call = 64 bytes
    state.SetBytesProcessed(state.iterations() * 64);
}
BENCHMARK(BM_SIMD_AVX2_Extract);

#endif // __AVX2__

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

static void BM_SIMD_NEON_Step(benchmark::State& state) {
    auto scalar_states = generate_random_states<4>(42);
    auto vs = detail::simd::neon::load_states(scalar_states.data());
    
    for (auto _ : state) {
        detail::simd::neon::step_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 4);
}
BENCHMARK(BM_SIMD_NEON_Step);

static void BM_SIMD_NEON_Warmup(benchmark::State& state) {
    auto scalar_states = generate_random_states<4>(42);
    
    for (auto _ : state) {
        auto vs = detail::simd::neon::load_states(scalar_states.data());
        detail::simd::neon::warmup_vec(vs);
        benchmark::DoNotOptimize(vs);
    }
    state.SetItemsProcessed(state.iterations() * 4);
}
BENCHMARK(BM_SIMD_NEON_Warmup);

static void BM_SIMD_NEON_Extract(benchmark::State& state) {
    auto scalar_states = generate_random_states<4>(42);
    auto vs = detail::simd::neon::load_states(scalar_states.data());
    uint32x4_t lo, hi;
    
    for (auto _ : state) {
        detail::simd::neon::extract_vec(vs, lo, hi);
        benchmark::DoNotOptimize(lo);
        benchmark::DoNotOptimize(hi);
    }
    // Extracts 4x 64-bit keystreams per call = 32 bytes
    state.SetBytesProcessed(state.iterations() * 32);
}
BENCHMARK(BM_SIMD_NEON_Extract);

#endif // __ARM_NEON
