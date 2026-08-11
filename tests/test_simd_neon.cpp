// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_simd_neon.cpp — NEON isolated test implementation

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

#include "test_simd_neon.hpp"
#include "eahcm/detail/simd/neon.hpp"

void neon_L_vec_compute(const std::uint32_t* v, const std::uint32_t* p, std::uint32_t* out) {
    uint32x4_t vec_v = vld1q_u32(v);
    uint32x4_t vec_p = vld1q_u32(p);
    uint32x4_t vec_out = eahcm::detail::simd::neon::L_vec(vec_v, vec_p);
    vst1q_u32(out, vec_out);
}

void neon_F_vec_compute(const std::uint32_t* v, std::uint32_t* out) {
    uint32x4_t vec_v = vld1q_u32(v);
    uint32x4_t vec_out = eahcm::detail::simd::neon::F_vec(vec_v);
    vst1q_u32(out, vec_out);
}

void neon_R_vec_compute(const std::uint32_t* w, std::uint32_t* out) {
    uint32x4_t vec_w = vld1q_u32(w);
    uint32x4_t vec_out = eahcm::detail::simd::neon::R_vec(vec_w);
    vst1q_u32(out, vec_out);
}

void neon_step_vec_compute(const eahcm::State* in_states, eahcm::State* out_states, int steps) {
    auto vec_state = eahcm::detail::simd::neon::load_states(in_states);
    for (int i = 0; i < steps; ++i) {
        eahcm::detail::simd::neon::step_vec(vec_state);
    }
    eahcm::detail::simd::neon::store_states(out_states, vec_state);
}

void neon_extract_vec_compute(const eahcm::State* in_states, std::uint64_t* out_extracts) {
    auto vec_state = eahcm::detail::simd::neon::load_states(in_states);
    uint32x4_t out_lo_2, out_hi_2;
    eahcm::detail::simd::neon::extract_vec(vec_state, out_lo_2, out_hi_2);
    alignas(16) std::uint64_t v_lo[2], v_hi[2];
    vst1q_u64((uint64_t*)v_lo, vreinterpretq_u64_u32(out_lo_2));
    vst1q_u64((uint64_t*)v_hi, vreinterpretq_u64_u32(out_hi_2));
    
    out_extracts[0] = v_lo[0];
    out_extracts[1] = v_lo[1];
    out_extracts[2] = v_hi[0];
    out_extracts[3] = v_hi[1];
}

#endif // __ARM_NEON
