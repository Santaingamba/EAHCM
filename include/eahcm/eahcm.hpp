// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// eahcm.hpp — Umbrella header for the EAHCM library.
//
// Include this single header to get the complete public API.
//
// Public API layers:
//   Stage 1 — key schedule, chaotic state machine, keystream cipher,
//              serialization
//   Stage 2 — ChaCha20-Poly1305 AEAD construction (aead.hpp)

#ifndef EAHCM_HPP
#define EAHCM_HPP

#include "eahcm/version.hpp"
#include "eahcm/config.hpp"
#include "eahcm/constants.hpp"
#include "eahcm/types.hpp"
#include "eahcm/bit_ops.hpp"
#include "eahcm/arithmetic.hpp"
#include "eahcm/state.hpp"
#include "eahcm/key_schedule.hpp"
#include "eahcm/cipher.hpp"
#include "eahcm/serialization.hpp"
#include "eahcm/exceptions.hpp"
#include "eahcm/aead.hpp"       // Stage 2: ChaCha20-Poly1305 AEAD

#endif // EAHCM_HPP
