// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_simd_neon.hpp — NEON isolated benchmark functions

#ifndef EAHCM_BENCH_SIMD_NEON_HPP
#define EAHCM_BENCH_SIMD_NEON_HPP

#include <benchmark/benchmark.h>

void BM_SIMD_NEON_Step(benchmark::State& state);
void BM_SIMD_NEON_Warmup(benchmark::State& state);
void BM_SIMD_NEON_Extract(benchmark::State& state);

#endif // EAHCM_BENCH_SIMD_NEON_HPP
