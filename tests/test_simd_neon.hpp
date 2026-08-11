// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_simd_neon.hpp — NEON isolated test functions

#ifndef EAHCM_TEST_SIMD_NEON_HPP
#define EAHCM_TEST_SIMD_NEON_HPP

#include <cstdint>
#include <array>
#include "eahcm/state.hpp"

// Pure stateless wrappers to execute NEON intrinsics
void neon_L_vec_compute(const std::uint32_t* v, const std::uint32_t* p, std::uint32_t* out);
void neon_F_vec_compute(const std::uint32_t* v, std::uint32_t* out);
void neon_R_vec_compute(const std::uint32_t* w, std::uint32_t* out);
void neon_step_vec_compute(const eahcm::State* in_states, eahcm::State* out_states, int steps);
void neon_extract_vec_compute(const eahcm::State* in_states, std::uint64_t* out_extracts);

#endif // EAHCM_TEST_SIMD_NEON_HPP
