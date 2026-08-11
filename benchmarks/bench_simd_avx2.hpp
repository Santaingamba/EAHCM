// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_simd_avx2.hpp — AVX2 isolated benchmark functions

#ifndef EAHCM_BENCH_SIMD_AVX2_HPP
#define EAHCM_BENCH_SIMD_AVX2_HPP

#include <benchmark/benchmark.h>

void BM_SIMD_AVX2_L(benchmark::State& state);
void BM_SIMD_AVX2_Step(benchmark::State& state);
void BM_SIMD_AVX2_Warmup(benchmark::State& state);
void BM_SIMD_AVX2_Extract(benchmark::State& state);

#endif // EAHCM_BENCH_SIMD_AVX2_HPP
