// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// avx2.hpp — AVX2 backend for EAHCM batch processing.
//
// Processes 8 independent EAHCM states simultaneously.
// MUST NOT change scalar semantics.

#ifndef EAHCM_SIMD_AVX2_HPP
#define EAHCM_SIMD_AVX2_HPP

#if defined(__AVX2__)
#include <cstdint>
#include <immintrin.h>

#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"
#include "eahcm/detail/simd/vector_state.hpp"
#include "eahcm/state.hpp" // For scalar fallback functions like clamp_param

namespace eahcm {
namespace detail {
namespace simd {

template <>
struct alignas(32) VectorState<8> {
    __m256i x;
    __m256i y;
    __m256i z;
    __m256i w;
    __m256i alpha;
    __m256i gamma;
    __m256i mu;
    __m256i sigma;
    __m256i counter;

    /// Read an element from a vector.
    EAHCM_FORCE_INLINE std::uint32_t get_x(int lane) const { return reinterpret_cast<const std::uint32_t*>(&x)[lane]; }
    EAHCM_FORCE_INLINE std::uint32_t get_y(int lane) const { return reinterpret_cast<const std::uint32_t*>(&y)[lane]; }
    EAHCM_FORCE_INLINE std::uint32_t get_z(int lane) const { return reinterpret_cast<const std::uint32_t*>(&z)[lane]; }
    EAHCM_FORCE_INLINE std::uint32_t get_w(int lane) const { return reinterpret_cast<const std::uint32_t*>(&w)[lane]; }
};

namespace avx2 {

/// Broadcast 8 scalar states into a VectorState<8>.
EAHCM_FORCE_INLINE VectorState<8> load_states(const State* states) noexcept {
    VectorState<8> vs;
    alignas(32) std::uint32_t px[8], py[8], pz[8], pw[8];
    alignas(32) std::uint32_t pa[8], pg[8], pm[8], ps[8], pc[8];

    for (int i = 0; i < 8; ++i) {
        px[i] = states[i].x;
        py[i] = states[i].y;
        pz[i] = states[i].z;
        pw[i] = states[i].w;
        pa[i] = states[i].alpha;
        pg[i] = states[i].gamma;
        pm[i] = states[i].mu;
        ps[i] = states[i].sigma;
        pc[i] = states[i].counter;
    }

    vs.x = _mm256_load_si256(reinterpret_cast<const __m256i*>(px));
    vs.y = _mm256_load_si256(reinterpret_cast<const __m256i*>(py));
    vs.z = _mm256_load_si256(reinterpret_cast<const __m256i*>(pz));
    vs.w = _mm256_load_si256(reinterpret_cast<const __m256i*>(pw));
    vs.alpha = _mm256_load_si256(reinterpret_cast<const __m256i*>(pa));
    vs.gamma = _mm256_load_si256(reinterpret_cast<const __m256i*>(pg));
    vs.mu = _mm256_load_si256(reinterpret_cast<const __m256i*>(pm));
    vs.sigma = _mm256_load_si256(reinterpret_cast<const __m256i*>(ps));
    vs.counter = _mm256_load_si256(reinterpret_cast<const __m256i*>(pc));
    
    return vs;
}

/// Store a VectorState<8> back to 8 scalar states.
EAHCM_FORCE_INLINE void store_states(State* states, const VectorState<8>& vs) noexcept {
    alignas(32) std::uint32_t px[8], py[8], pz[8], pw[8];
    alignas(32) std::uint32_t pa[8], pg[8], pm[8], ps[8], pc[8];

    _mm256_store_si256(reinterpret_cast<__m256i*>(px), vs.x);
    _mm256_store_si256(reinterpret_cast<__m256i*>(py), vs.y);
    _mm256_store_si256(reinterpret_cast<__m256i*>(pz), vs.z);
    _mm256_store_si256(reinterpret_cast<__m256i*>(pw), vs.w);
    _mm256_store_si256(reinterpret_cast<__m256i*>(pa), vs.alpha);
    _mm256_store_si256(reinterpret_cast<__m256i*>(pg), vs.gamma);
    _mm256_store_si256(reinterpret_cast<__m256i*>(pm), vs.mu);
    _mm256_store_si256(reinterpret_cast<__m256i*>(ps), vs.sigma);
    _mm256_store_si256(reinterpret_cast<__m256i*>(pc), vs.counter);

    for (int i = 0; i < 8; ++i) {
        states[i].x = px[i];
        states[i].y = py[i];
        states[i].z = pz[i];
        states[i].w = pw[i];
        states[i].alpha = pa[i];
        states[i].gamma = pg[i];
        states[i].mu = pm[i];
        states[i].sigma = ps[i];
        states[i].counter = pc[i];
    }
}

template <int C>
EAHCM_FORCE_INLINE __m256i rol32_vec(__m256i w) noexcept {
    if constexpr (C == 0) return w;
    return _mm256_or_si256(_mm256_slli_epi32(w, C), _mm256_srli_epi32(w, 32 - C));
}

/// AVX2 Vectorized L(v, p)
EAHCM_FORCE_INLINE __m256i L_vec(__m256i v, __m256i p) noexcept {
    __m256i not_v = _mm256_andnot_si256(v, _mm256_set1_epi32(-1));
    __m256i v_odd = _mm256_srli_epi64(v, 32);
    __m256i not_v_odd = _mm256_srli_epi64(not_v, 32);

    __m256i vn_even = _mm256_mul_epu32(v, not_v);
    __m256i vn_odd = _mm256_mul_epu32(v_odd, not_v_odd);

    __m256i p_odd = _mm256_srli_epi64(p, 32);

    __m256i term1_even = _mm256_mul_epu32(p, _mm256_srli_epi64(vn_even, 32));
    __m256i term2_even = _mm256_mul_epu32(p, vn_even);
    __m256i res_even = _mm256_add_epi64(term1_even, _mm256_srli_epi64(term2_even, 32));

    __m256i term1_odd = _mm256_mul_epu32(p_odd, _mm256_srli_epi64(vn_odd, 32));
    __m256i term2_odd = _mm256_mul_epu32(p_odd, vn_odd);
    __m256i res_odd = _mm256_add_epi64(term1_odd, _mm256_srli_epi64(term2_odd, 32));

    __m256i res_odd_shifted = _mm256_slli_epi64(res_odd, 32);
    __m256i result = _mm256_blend_epi32(res_even, res_odd_shifted, 0xAA);

    __m256i is_zero = _mm256_cmpeq_epi32(result, _mm256_setzero_si256());
    result = _mm256_sub_epi32(result, is_zero); // result -= (0xFFFFFFFF) == result + 1
    return result;
}

/// AVX2 Vectorized F(v)
EAHCM_FORCE_INLINE __m256i F_vec(__m256i v) noexcept {
    __m256i mask = _mm256_srai_epi32(v, 31);
    __m256i folded = _mm256_slli_epi32(_mm256_xor_si256(v, mask), 1);
    __m256i is_zero = _mm256_cmpeq_epi32(folded, _mm256_setzero_si256());
    __m256i fix = _mm256_and_si256(is_zero, _mm256_set1_epi32(PHI_FRAC));
    return _mm256_xor_si256(folded, fix);
}

/// AVX2 Vectorized R(w)
EAHCM_FORCE_INLINE __m256i R_vec(__m256i w) noexcept {
    __m256i r13 = rol32_vec<13>(w);
    __m256i r7 = rol32_vec<7>(w);
    __m256i r3 = _mm256_srli_epi32(w, 3);
    return _mm256_xor_si256(_mm256_xor_si256(r13, r7), r3);
}

/// AVX2 Vectorized parameter drift
EAHCM_FORCE_INLINE void drift_parameters_vec(VectorState<8>& vs, __m256i x_prev, __m256i y_prev, __m256i z_prev, __m256i w_prev) noexcept {
    __m256i drift_mask_const = _mm256_set1_epi32(DRIFT_INTERVAL - 1);
    __m256i is_drift = _mm256_cmpeq_epi32(_mm256_and_si256(vs.counter, drift_mask_const), _mm256_setzero_si256());
    
    int mask = _mm256_movemask_ps(_mm256_castsi256_ps(is_drift));
    if (mask == 0) return; // Fast path: no lanes need drift

    // Slow path: scalar clamp for drifting lanes
    alignas(32) std::uint32_t a_buf[8], g_buf[8], m_buf[8], sig_buf[8];
    alignas(32) std::uint32_t xp_buf[8], yp_buf[8], zp_buf[8], wp_buf[8];
    alignas(32) std::uint32_t c_buf[8];

    _mm256_store_si256(reinterpret_cast<__m256i*>(a_buf), vs.alpha);
    _mm256_store_si256(reinterpret_cast<__m256i*>(g_buf), vs.gamma);
    _mm256_store_si256(reinterpret_cast<__m256i*>(m_buf), vs.mu);
    _mm256_store_si256(reinterpret_cast<__m256i*>(sig_buf), vs.sigma);
    _mm256_store_si256(reinterpret_cast<__m256i*>(xp_buf), x_prev);
    _mm256_store_si256(reinterpret_cast<__m256i*>(yp_buf), y_prev);
    _mm256_store_si256(reinterpret_cast<__m256i*>(zp_buf), z_prev);
    _mm256_store_si256(reinterpret_cast<__m256i*>(wp_buf), w_prev);
    _mm256_store_si256(reinterpret_cast<__m256i*>(c_buf), vs.counter);

    for (int i = 0; i < 8; ++i) {
        if ((c_buf[i] & (DRIFT_INTERVAL - 1)) == 0) {
            std::uint32_t fold = xp_buf[i] ^ yp_buf[i] ^ zp_buf[i] ^ wp_buf[i];
            a_buf[i] = clamp_param(a_buf[i] ^ rol32(fold, ROT_DRIFT_ALPHA));
            g_buf[i] = clamp_param(g_buf[i] ^ rol32(fold, ROT_DRIFT_GAMMA));
            m_buf[i] = clamp_param(m_buf[i] ^ rol32(fold, ROT_DRIFT_MU));
            sig_buf[i] = clamp_param(sig_buf[i] ^ rol32(fold, ROT_DRIFT_SIGMA));
        }
    }

    vs.alpha = _mm256_load_si256(reinterpret_cast<const __m256i*>(a_buf));
    vs.gamma = _mm256_load_si256(reinterpret_cast<const __m256i*>(g_buf));
    vs.mu = _mm256_load_si256(reinterpret_cast<const __m256i*>(m_buf));
    vs.sigma = _mm256_load_si256(reinterpret_cast<const __m256i*>(sig_buf));
}

/// AVX2 Vectorized step
EAHCM_FORCE_INLINE void step_vec(VectorState<8>& vs) noexcept {
    __m256i x = vs.x;
    __m256i y = vs.y;
    __m256i z = vs.z;
    __m256i w = vs.w;

    __m256i eps = _mm256_xor_si256(rol32_vec<ROT_CTR_EPS>(vs.counter), _mm256_set1_epi32(EPSILON_CONST));
    vs.counter = _mm256_add_epi32(vs.counter, _mm256_set1_epi32(1));

    vs.x = _mm256_add_epi32(_mm256_add_epi32(L_vec(x, vs.alpha), _mm256_xor_si256(F_vec(z), rol32_vec<ROT_Y_IN_X>(y))), eps);
    vs.y = _mm256_add_epi32(L_vec(y, vs.gamma), _mm256_xor_si256(R_vec(w), rol32_vec<ROT_X_IN_Y>(x)));
    vs.z = _mm256_add_epi32(L_vec(z, vs.mu), _mm256_xor_si256(F_vec(x), rol32_vec<ROT_W_IN_Z>(w)));
    vs.w = _mm256_add_epi32(L_vec(w, vs.sigma), _mm256_xor_si256(R_vec(y), rol32_vec<ROT_Z_IN_W>(z)));

    drift_parameters_vec(vs, x, y, z, w);
}

/// AVX2 Vectorized extraction
/// Extract produces 8x 64-bit keystream outputs. Since we cannot cleanly return
/// 8x 64-bit outputs in __m256i (it only holds 4), we return them in two vectors.
EAHCM_FORCE_INLINE void extract_vec(const VectorState<8>& vs, __m256i& out_lo_4, __m256i& out_hi_4) noexcept {
    __m256i hi = _mm256_xor_si256(_mm256_add_epi32(vs.x, vs.z), rol32_vec<ROT_EXTRACT>(vs.y));
    __m256i lo = _mm256_xor_si256(_mm256_add_epi32(vs.y, vs.w), rol32_vec<ROT_EXTRACT>(vs.x));
    
    // Interleave lo and hi into 64-bit blocks
    // hi contains: H0, H1, H2, H3, H4, H5, H6, H7
    // lo contains: L0, L1, L2, L3, L4, L5, L6, L7
    // We want: L0 H0, L1 H1, L2 H2, L3 H3 in one vector
    // And L4 H4, L5 H5, L6 H6, L7 H7 in another.
    
    // First, interleave 32-bit within 128-bit lanes
    __m256i lo_hi_even = _mm256_unpacklo_epi32(lo, hi); // L0 H0, L1 H1 | L4 H4, L5 H5
    __m256i lo_hi_odd  = _mm256_unpackhi_epi32(lo, hi); // L2 H2, L3 H3 | L6 H6, L7 H7
    
    // out_lo_4 = L0 H0 L1 H1 | L2 H2 L3 H3
    out_lo_4 = _mm256_permute2x128_si256(lo_hi_even, lo_hi_odd, 0x20);
    // out_hi_4 = L4 H4 L5 H5 | L6 H6 L7 H7
    out_hi_4 = _mm256_permute2x128_si256(lo_hi_even, lo_hi_odd, 0x31);
}

/// AVX2 Vectorized warmup
EAHCM_FORCE_INLINE void warmup_vec(VectorState<8>& vs) noexcept {
    for (std::uint32_t i = 0; i < WARMUP_STEPS; ++i) {
        step_vec(vs);
    }
}

} // namespace avx2
} // namespace simd
} // namespace detail
} // namespace eahcm
#endif // __AVX2__

#endif // EAHCM_SIMD_AVX2_HPP
