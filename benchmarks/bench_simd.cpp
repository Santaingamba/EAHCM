// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_simd.cpp — Benchmarks for SIMD batched processing.

#include <benchmark/benchmark.h>
#include "eahcm/detail/simd/detect.hpp"

#if defined(__AVX2__) || defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#define EAHCM_HAS_AVX2_BENCHMARKS
#include "bench_simd_avx2.hpp"
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON) || defined(__ARM_NEON__)
#define EAHCM_HAS_NEON_BENCHMARKS
#include "bench_simd_neon.hpp"
#endif

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;

#if defined(EAHCM_HAS_AVX2_BENCHMARKS)
    if (eahcm::detail::simd::cpu_supports_avx2()) {
        ::benchmark::RegisterBenchmark("BM_SIMD_AVX2_L", BM_SIMD_AVX2_L);
        ::benchmark::RegisterBenchmark("BM_SIMD_AVX2_Step", BM_SIMD_AVX2_Step);
        ::benchmark::RegisterBenchmark("BM_SIMD_AVX2_Warmup", BM_SIMD_AVX2_Warmup);
        ::benchmark::RegisterBenchmark("BM_SIMD_AVX2_Extract", BM_SIMD_AVX2_Extract);
    }
#endif

#if defined(EAHCM_HAS_NEON_BENCHMARKS)
    ::benchmark::RegisterBenchmark("BM_SIMD_NEON_Step", BM_SIMD_NEON_Step);
    ::benchmark::RegisterBenchmark("BM_SIMD_NEON_Warmup", BM_SIMD_NEON_Warmup);
    ::benchmark::RegisterBenchmark("BM_SIMD_NEON_Extract", BM_SIMD_NEON_Extract);
#endif

    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();
    return 0;
}
