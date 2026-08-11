// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// neon.hpp — ARM NEON backend for EAHCM batch processing.
//
// Processes 4 independent EAHCM states simultaneously.
// MUST NOT change scalar semantics.

#ifndef EAHCM_SIMD_NEON_HPP
#define EAHCM_SIMD_NEON_HPP

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <cstdint>
#include <arm_neon.h>

#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"
#include "eahcm/detail/simd/vector_state.hpp"
#include "eahcm/state.hpp" // For scalar fallback functions like clamp_param

namespace eahcm {
namespace detail {
namespace simd {

template <>
struct alignas(16) VectorState<4> {
    uint32x4_t x;
    uint32x4_t y;
    uint32x4_t z;
    uint32x4_t w;
    uint32x4_t alpha;
    uint32x4_t gamma;
    uint32x4_t mu;
    uint32x4_t sigma;
    uint32x4_t counter;

    /// Read an element from a vector.
    EAHCM_FORCE_INLINE std::uint32_t get_x(int lane) const { alignas(16) std::uint32_t temp[4]; vst1q_u32(temp, x); return temp[lane]; }
    EAHCM_FORCE_INLINE std::uint32_t get_y(int lane) const { alignas(16) std::uint32_t temp[4]; vst1q_u32(temp, y); return temp[lane]; }
    EAHCM_FORCE_INLINE std::uint32_t get_z(int lane) const { alignas(16) std::uint32_t temp[4]; vst1q_u32(temp, z); return temp[lane]; }
    EAHCM_FORCE_INLINE std::uint32_t get_w(int lane) const { alignas(16) std::uint32_t temp[4]; vst1q_u32(temp, w); return temp[lane]; }
};

namespace neon {

/// Broadcast 4 scalar states into a VectorState<4>.
EAHCM_FORCE_INLINE VectorState<4> load_states(const State* states) noexcept {
    VectorState<4> vs;
    alignas(16) std::uint32_t px[4], py[4], pz[4], pw[4];
    alignas(16) std::uint32_t pa[4], pg[4], pm[4], ps[4], pc[4];

    for (int i = 0; i < 4; ++i) {
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

    vs.x = vld1q_u32(px);
    vs.y = vld1q_u32(py);
    vs.z = vld1q_u32(pz);
    vs.w = vld1q_u32(pw);
    vs.alpha = vld1q_u32(pa);
    vs.gamma = vld1q_u32(pg);
    vs.mu = vld1q_u32(pm);
    vs.sigma = vld1q_u32(ps);
    vs.counter = vld1q_u32(pc);
    
    return vs;
}

/// Store a VectorState<4> back to 4 scalar states.
EAHCM_FORCE_INLINE void store_states(State* states, const VectorState<4>& vs) noexcept {
    alignas(16) std::uint32_t px[4], py[4], pz[4], pw[4];
    alignas(16) std::uint32_t pa[4], pg[4], pm[4], ps[4], pc[4];

    vst1q_u32(px, vs.x);
    vst1q_u32(py, vs.y);
    vst1q_u32(pz, vs.z);
    vst1q_u32(pw, vs.w);
    vst1q_u32(pa, vs.alpha);
    vst1q_u32(pg, vs.gamma);
    vst1q_u32(pm, vs.mu);
    vst1q_u32(ps, vs.sigma);
    vst1q_u32(pc, vs.counter);

    for (int i = 0; i < 4; ++i) {
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
EAHCM_FORCE_INLINE uint32x4_t rol32_vec(uint32x4_t w) noexcept {
    if constexpr (C == 0) return w;
    return vorrq_u32(vshlq_n_u32(w, C), vshrq_n_u32(w, 32 - C));
}

/// NEON Vectorized L(v, p)
EAHCM_FORCE_INLINE uint32x4_t L_vec(uint32x4_t v, uint32x4_t p) noexcept {
    uint32x4_t not_v = vmvnq_u32(v);
    
    uint64x2_t vn_low = vmull_u32(vget_low_u32(v), vget_low_u32(not_v));
    uint64x2_t vn_high = vmull_u32(vget_high_u32(v), vget_high_u32(not_v));
    
    uint32x2_t vn_low_hi32 = vmovn_u64(vshrq_n_u64(vn_low, 32));
    uint32x2_t vn_low_lo32 = vmovn_u64(vn_low);
    uint32x2_t p_low = vget_low_u32(p);
    
    uint64x2_t term1_low = vmull_u32(p_low, vn_low_hi32);
    uint64x2_t term2_low = vmull_u32(p_low, vn_low_lo32);
    uint64x2_t res_low = vaddq_u64(term1_low, vshrq_n_u64(term2_low, 32));
    
    uint32x2_t vn_high_hi32 = vmovn_u64(vshrq_n_u64(vn_high, 32));
    uint32x2_t vn_high_lo32 = vmovn_u64(vn_high);
    uint32x2_t p_high = vget_high_u32(p);
    
    uint64x2_t term1_high = vmull_u32(p_high, vn_high_hi32);
    uint64x2_t term2_high = vmull_u32(p_high, vn_high_lo32);
    uint64x2_t res_high = vaddq_u64(term1_high, vshrq_n_u64(term2_high, 32));
    
    uint32x4_t result = vcombine_u32(vmovn_u64(res_low), vmovn_u64(res_high));
    
    uint32x4_t is_zero = vceqq_u32(result, vdupq_n_u32(0));
    result = vsubq_u32(result, is_zero);
    return result;
}

/// NEON Vectorized F(v)
EAHCM_FORCE_INLINE uint32x4_t F_vec(uint32x4_t v) noexcept {
    uint32x4_t mask = vreinterpretq_u32_s32(vshrq_n_s32(vreinterpretq_s32_u32(v), 31));
    uint32x4_t folded = vshlq_n_u32(veorq_u32(v, mask), 1);
    uint32x4_t is_zero = vceqq_u32(folded, vdupq_n_u32(0));
    uint32x4_t fix = vandq_u32(is_zero, vdupq_n_u32(PHI_FRAC));
    return veorq_u32(folded, fix);
}

/// NEON Vectorized R(w)
EAHCM_FORCE_INLINE uint32x4_t R_vec(uint32x4_t w) noexcept {
    uint32x4_t r13 = rol32_vec<13>(w);
    uint32x4_t r7 = rol32_vec<7>(w);
    uint32x4_t r3 = vshrq_n_u32(w, 3);
    return veorq_u32(veorq_u32(r13, r7), r3);
}

/// NEON Vectorized parameter drift
EAHCM_FORCE_INLINE void drift_parameters_vec(VectorState<4>& vs, uint32x4_t x_prev, uint32x4_t y_prev, uint32x4_t z_prev, uint32x4_t w_prev) noexcept {
    uint32x4_t drift_mask_const = vdupq_n_u32(DRIFT_INTERVAL - 1);
    uint32x4_t is_drift = vceqq_u32(vandq_u32(vs.counter, drift_mask_const), vdupq_n_u32(0));
    
    // Check if any lane is drifting.
    // NEON doesn't have an easy movemask. We can extract lanes or use vmaxvq_u32
#if defined(__aarch64__)
    if (vmaxvq_u32(is_drift) == 0) return;
#else
    uint32x2_t low_max = vmax_u32(vget_low_u32(is_drift), vget_high_u32(is_drift));
    if (vget_lane_u32(low_max, 0) == 0 && vget_lane_u32(low_max, 1) == 0) return;
#endif

    alignas(16) std::uint32_t a_buf[4], g_buf[4], m_buf[4], sig_buf[4];
    alignas(16) std::uint32_t xp_buf[4], yp_buf[4], zp_buf[4], wp_buf[4];
    alignas(16) std::uint32_t c_buf[4];

    vst1q_u32(a_buf, vs.alpha);
    vst1q_u32(g_buf, vs.gamma);
    vst1q_u32(m_buf, vs.mu);
    vst1q_u32(sig_buf, vs.sigma);
    vst1q_u32(xp_buf, x_prev);
    vst1q_u32(yp_buf, y_prev);
    vst1q_u32(zp_buf, z_prev);
    vst1q_u32(wp_buf, w_prev);
    vst1q_u32(c_buf, vs.counter);

    for (int i = 0; i < 4; ++i) {
        if ((c_buf[i] & (DRIFT_INTERVAL - 1)) == 0) {
            std::uint32_t fold = xp_buf[i] ^ yp_buf[i] ^ zp_buf[i] ^ wp_buf[i];
            a_buf[i] = clamp_param(a_buf[i] ^ rol32(fold, ROT_DRIFT_ALPHA));
            g_buf[i] = clamp_param(g_buf[i] ^ rol32(fold, ROT_DRIFT_GAMMA));
            m_buf[i] = clamp_param(m_buf[i] ^ rol32(fold, ROT_DRIFT_MU));
            sig_buf[i] = clamp_param(sig_buf[i] ^ rol32(fold, ROT_DRIFT_SIGMA));
        }
    }

    vs.alpha = vld1q_u32(a_buf);
    vs.gamma = vld1q_u32(g_buf);
    vs.mu = vld1q_u32(m_buf);
    vs.sigma = vld1q_u32(sig_buf);
}

/// NEON Vectorized step
EAHCM_FORCE_INLINE void step_vec(VectorState<4>& vs) noexcept {
    uint32x4_t x = vs.x;
    uint32x4_t y = vs.y;
    uint32x4_t z = vs.z;
    uint32x4_t w = vs.w;

    uint32x4_t eps = veorq_u32(rol32_vec<ROT_CTR_EPS>(vs.counter), vdupq_n_u32(EPSILON_CONST));
    vs.counter = vaddq_u32(vs.counter, vdupq_n_u32(1));

    vs.x = vaddq_u32(vaddq_u32(L_vec(x, vs.alpha), veorq_u32(F_vec(z), rol32_vec<ROT_Y_IN_X>(y))), eps);
    vs.y = vaddq_u32(L_vec(y, vs.gamma), veorq_u32(R_vec(w), rol32_vec<ROT_X_IN_Y>(x)));
    vs.z = vaddq_u32(L_vec(z, vs.mu), veorq_u32(F_vec(x), rol32_vec<ROT_W_IN_Z>(w)));
    vs.w = vaddq_u32(L_vec(w, vs.sigma), veorq_u32(R_vec(y), rol32_vec<ROT_Z_IN_W>(z)));

    drift_parameters_vec(vs, x, y, z, w);
}

/// NEON Vectorized extraction
EAHCM_FORCE_INLINE void extract_vec(const VectorState<4>& vs, uint32x4_t& out_lo_2, uint32x4_t& out_hi_2) noexcept {
    uint32x4_t hi = veorq_u32(vaddq_u32(vs.x, vs.z), rol32_vec<ROT_EXTRACT>(vs.y));
    uint32x4_t lo = veorq_u32(vaddq_u32(vs.y, vs.w), rol32_vec<ROT_EXTRACT>(vs.x));
    
    // We want to interleave lo and hi into 64-bit blocks
    // hi contains: H0, H1, H2, H3
    // lo contains: L0, L1, L2, L3
    // vtrn or vzip could work, but zip1/zip2 are easiest.
#if defined(__aarch64__)
    out_lo_2 = vzip1q_u32(lo, hi); // L0 H0 L1 H1
    out_hi_2 = vzip2q_u32(lo, hi); // L2 H2 L3 H3
#else
    uint32x4x2_t zipped = vzipq_u32(lo, hi);
    out_lo_2 = zipped.val[0];
    out_hi_2 = zipped.val[1];
#endif
}

/// NEON Vectorized warmup
EAHCM_FORCE_INLINE void warmup_vec(VectorState<4>& vs) noexcept {
    for (std::uint32_t i = 0; i < WARMUP_STEPS; ++i) {
        step_vec(vs);
    }
}

} // namespace neon
} // namespace simd
} // namespace detail
} // namespace eahcm
#endif // __ARM_NEON

#endif // EAHCM_SIMD_NEON_HPP
