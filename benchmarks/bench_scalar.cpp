// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// bench_scalar.cpp — Performance baselines for the EAHCM scalar implementation.
//
// Measures:
//  - Primitives (L, F, R)
//  - State evolution (step, warmup, extract)
//  - Key derivation
//  - Keystream generation (Cipher::generate)
//  - AEAD ChaCha20-Poly1305 encryption/decryption (payloads 64B to 1MiB)

#include <benchmark/benchmark.h>

#include "eahcm/arithmetic.hpp"
#include "eahcm/state.hpp"
#include "eahcm/cipher.hpp"
#include "eahcm/aead.hpp"
#include "eahcm/key_schedule.hpp"

#include <vector>

using namespace eahcm;

// =========================================================================
// Benchmark: Primitives
// =========================================================================

static void BM_Scalar_Primitive_L(benchmark::State& state) {
    std::uint32_t v = 0x12345678;
    std::uint32_t p = 0x9ABCDEF0;
    for (auto _ : state) {
        v = L(v, p);
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_Scalar_Primitive_L);

static void BM_Scalar_Primitive_F(benchmark::State& state) {
    std::uint32_t v = 0x12345678;
    for (auto _ : state) {
        v = F(v);
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_Scalar_Primitive_F);

static void BM_Scalar_Primitive_R(benchmark::State& state) {
    std::uint32_t v = 0x12345678;
    for (auto _ : state) {
        v = R(v);
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_Scalar_Primitive_R);

// =========================================================================
// Benchmark: State Evolution
// =========================================================================

static void BM_Scalar_State_Step(benchmark::State& state) {
    State s = make_state(1, 2, 3, 4, 0x11111111, 0x22222222, 0x33333333, 0x44444444);
    for (auto _ : state) {
        step(s);
        benchmark::DoNotOptimize(s);
    }
}
BENCHMARK(BM_Scalar_State_Step);

static void BM_Scalar_State_Warmup(benchmark::State& state) {
    for (auto _ : state) {
        State s = make_state(1, 2, 3, 4, 0x11111111, 0x22222222, 0x33333333, 0x44444444);
        warmup(s);
        benchmark::DoNotOptimize(s);
    }
}
BENCHMARK(BM_Scalar_State_Warmup);

static void BM_Scalar_State_Extract(benchmark::State& state) {
    State s = make_state(1, 2, 3, 4, 0x11111111, 0x22222222, 0x33333333, 0x44444444);
    for (auto _ : state) {
        auto val = extract(s);
        benchmark::DoNotOptimize(val);
        // We step to prevent the compiler from caching the extraction
        step(s); 
    }
}
BENCHMARK(BM_Scalar_State_Extract);

// =========================================================================
// Benchmark: Key Derivation
// =========================================================================

static void BM_Scalar_Key_Derivation(benchmark::State& state) {
    const std::vector<uint8_t> key(32, 0xAA);
    const std::vector<uint8_t> nonce(12, 0xBB);
    
    for (auto _ : state) {
        auto s = derive_state(key, nonce, {});
        benchmark::DoNotOptimize(s);
    }
}
BENCHMARK(BM_Scalar_Key_Derivation);

// =========================================================================
// Benchmark: Raw Keystream Generation
// =========================================================================

static void BM_Scalar_Cipher_Generate(benchmark::State& state) {
    const size_t bytes = state.range(0);
    std::vector<uint8_t> buf(bytes);
    const std::vector<uint8_t> key(32, 0xAA);
    const std::vector<uint8_t> nonce(12, 0xBB);
    
    Cipher cipher(key, nonce);

    for (auto _ : state) {
        cipher.generate(buf);
        benchmark::DoNotOptimize(buf.data());
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(bytes));
}
BENCHMARK(BM_Scalar_Cipher_Generate)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096)
    ->Arg(16384)
    ->Arg(65536)
    ->Arg(1048576);

// =========================================================================
// Benchmark: AEAD ChaCha20-Poly1305
// =========================================================================

static void BM_Scalar_AEAD_Encrypt(benchmark::State& state) {
    const size_t bytes = state.range(0);
    std::vector<uint8_t> pt(bytes, 0x11);
    const std::vector<uint8_t> key(32, 0xAA);
    const std::vector<uint8_t> nonce(12, 0xBB);
    const std::vector<uint8_t> cnonce(12, 0xCC);
    const std::vector<uint8_t> aad;
    
    AeadCipher cipher(key, nonce);

    for (auto _ : state) {
        auto ct = cipher.encrypt(cnonce, aad, pt);
        benchmark::DoNotOptimize(ct);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(bytes));
}
BENCHMARK(BM_Scalar_AEAD_Encrypt)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096)
    ->Arg(16384)
    ->Arg(65536)
    ->Arg(1048576);

static void BM_Scalar_AEAD_Decrypt(benchmark::State& state) {
    const size_t bytes = state.range(0);
    std::vector<uint8_t> pt(bytes, 0x11);
    const std::vector<uint8_t> key(32, 0xAA);
    const std::vector<uint8_t> nonce(12, 0xBB);
    const std::vector<uint8_t> cnonce(12, 0xCC);
    const std::vector<uint8_t> aad;
    
    AeadCipher cipher(key, nonce);
    auto ct_data = cipher.encrypt(cnonce, aad, pt);

    for (auto _ : state) {
        cipher.reset(); // Must reset state to decrypt identical ciphertext repeatedly
        auto dec = cipher.decrypt(cnonce, aad, ct_data.ciphertext, ct_data.tag);
        benchmark::DoNotOptimize(dec);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(bytes));
}
BENCHMARK(BM_Scalar_AEAD_Decrypt)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096)
    ->Arg(16384)
    ->Arg(65536)
    ->Arg(1048576);
