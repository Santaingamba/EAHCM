// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_simd_avx2.hpp — AVX2 isolated test functions

#ifndef EAHCM_TEST_SIMD_AVX2_HPP
#define EAHCM_TEST_SIMD_AVX2_HPP

#include <cstdint>
#include <array>
#include "eahcm/state.hpp"

// Pure stateless wrappers to execute AVX2 intrinsics
void avx2_L_vec_compute(const std::uint32_t* v, const std::uint32_t* p, std::uint32_t* out);
void avx2_F_vec_compute(const std::uint32_t* v, std::uint32_t* out);
void avx2_R_vec_compute(const std::uint32_t* w, std::uint32_t* out);
void avx2_step_vec_compute(const eahcm::State* in_states, eahcm::State* out_states, int steps);
void avx2_extract_vec_compute(const eahcm::State* in_states, std::uint64_t* out_extracts);

#endif // EAHCM_TEST_SIMD_AVX2_HPP
