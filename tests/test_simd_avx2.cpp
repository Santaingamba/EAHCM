// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_simd_avx2.cpp — AVX2 isolated test implementation

#if defined(__AVX2__)

#include "test_simd_avx2.hpp"
#include "eahcm/detail/simd/avx2.hpp"

void avx2_L_vec_compute(const std::uint32_t* v, const std::uint32_t* p, std::uint32_t* out) {
    __m256i vec_v = _mm256_load_si256((__m256i*)v);
    __m256i vec_p = _mm256_load_si256((__m256i*)p);
    __m256i vec_out = eahcm::detail::simd::avx2::L_vec(vec_v, vec_p);
    _mm256_store_si256((__m256i*)out, vec_out);
}

void avx2_F_vec_compute(const std::uint32_t* v, std::uint32_t* out) {
    __m256i vec_v = _mm256_load_si256((__m256i*)v);
    __m256i vec_out = eahcm::detail::simd::avx2::F_vec(vec_v);
    _mm256_store_si256((__m256i*)out, vec_out);
}

void avx2_R_vec_compute(const std::uint32_t* w, std::uint32_t* out) {
    __m256i vec_w = _mm256_load_si256((__m256i*)w);
    __m256i vec_out = eahcm::detail::simd::avx2::R_vec(vec_w);
    _mm256_store_si256((__m256i*)out, vec_out);
}

void avx2_step_vec_compute(const eahcm::State* in_states, eahcm::State* out_states, int steps) {
    auto vec_state = eahcm::detail::simd::avx2::load_states(in_states);
    for (int i = 0; i < steps; ++i) {
        eahcm::detail::simd::avx2::step_vec(vec_state);
    }
    eahcm::detail::simd::avx2::store_states(out_states, vec_state);
}

void avx2_extract_vec_compute(const eahcm::State* in_states, std::uint64_t* out_extracts) {
    auto vec_state = eahcm::detail::simd::avx2::load_states(in_states);
    __m256i out_lo_4, out_hi_4;
    eahcm::detail::simd::avx2::extract_vec(vec_state, out_lo_4, out_hi_4);
    alignas(32) std::uint64_t v_lo[4], v_hi[4];
    _mm256_store_si256((__m256i*)v_lo, out_lo_4);
    _mm256_store_si256((__m256i*)v_hi, out_hi_4);
    
    out_extracts[0] = v_lo[0]; out_extracts[1] = v_lo[1];
    out_extracts[2] = v_lo[2]; out_extracts[3] = v_lo[3];
    out_extracts[4] = v_hi[0]; out_extracts[5] = v_hi[1];
    out_extracts[6] = v_hi[2]; out_extracts[7] = v_hi[3];
}

#endif // __AVX2__
