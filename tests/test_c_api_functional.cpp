// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// test_c_api_functional.cpp — Equivalence testing C vs C++ API.

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "eahcm/eahcm.h"
#include "eahcm/aead.hpp"
#include "eahcm/cipher.hpp"

#include <vector>
#include <cstring>

using namespace eahcm;

static std::vector<uint8_t> make_bytes(size_t count, uint8_t fill = 0xAB) {
    return std::vector<uint8_t>(count, fill);
}

// =========================================================================
// Equivalence Tests: Stateless AEAD
// =========================================================================

TEST_CASE("C API matches C++ API for stateless AEAD", "[c_api][aead]") {
    const auto key    = make_bytes(32, 0x11);
    const auto enonce = make_bytes(12, 0x22);
    const auto cnonce = make_bytes(12, 0x33);
    const auto pt     = make_bytes(64, 0x44);
    const auto aad    = make_bytes(16, 0x55);

    // C++ Baseline
    const auto [ct_cpp, tag_cpp] = aead_encrypt(key, enonce, cnonce, aad, pt);

    // C API
    std::vector<uint8_t> ct_c(pt.size());
    std::vector<uint8_t> tag_c(AEAD_TAG_SIZE);
    
    eahcm_error_t err = eahcm_aead_encrypt(
        key.data(), key.size(),
        enonce.data(), enonce.size(),
        cnonce.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        ct_c.data(), tag_c.data()
    );

    REQUIRE(err == EAHCM_SUCCESS);
    REQUIRE(ct_c == ct_cpp);
    REQUIRE(tag_c == std::vector<uint8_t>(tag_cpp.begin(), tag_cpp.end()));

    // Decrypt with C API
    std::vector<uint8_t> dec_c(ct_c.size());
    err = eahcm_aead_decrypt(
        key.data(), key.size(),
        enonce.data(), enonce.size(),
        cnonce.data(),
        aad.data(), aad.size(),
        ct_c.data(), ct_c.size(),
        tag_c.data(),
        dec_c.data()
    );

    REQUIRE(err == EAHCM_SUCCESS);
    REQUIRE(dec_c == pt);
}

// =========================================================================
// Equivalence Tests: Stateful AEAD
// =========================================================================

TEST_CASE("C API matches C++ API for stateful AEAD", "[c_api][aead]") {
    const auto key    = make_bytes(32, 0xAA);
    const auto enonce = make_bytes(12, 0xBB);
    const auto cnonce = make_bytes(12, 0xCC);
    const auto pt     = make_bytes(100, 0xDD);

    AeadCipher cpp_ctx(key, enonce);
    
    eahcm_aead_ctx* c_ctx = nullptr;
    eahcm_error_t err = eahcm_aead_create(&c_ctx, key.data(), key.size(), enonce.data(), enonce.size(), nullptr, 0);
    REQUIRE(err == EAHCM_SUCCESS);
    REQUIRE(c_ctx != nullptr);

    // Encrypt
    const auto [ct_cpp, tag_cpp] = cpp_ctx.encrypt(cnonce, {}, pt);
    
    std::vector<uint8_t> ct_c(pt.size());
    std::vector<uint8_t> tag_c(AEAD_TAG_SIZE);
    err = eahcm_aead_encrypt_message(c_ctx, cnonce.data(), nullptr, 0, pt.data(), pt.size(), ct_c.data(), tag_c.data());
    
    REQUIRE(err == EAHCM_SUCCESS);
    REQUIRE(ct_c == ct_cpp);
    REQUIRE(tag_c == std::vector<uint8_t>(tag_cpp.begin(), tag_cpp.end()));

    // Seal
    const auto blob_cpp = cpp_ctx.seal(cnonce, {}, pt);
    
    size_t req_size = eahcm_aead_sealed_size(pt.size());
    REQUIRE(req_size == CONTAINER_MIN_SIZE + pt.size());
    
    std::vector<uint8_t> blob_c(req_size);
    size_t written = 0;
    err = eahcm_aead_seal(c_ctx, cnonce.data(), nullptr, 0, pt.data(), pt.size(), blob_c.data(), blob_c.size(), &written);
    
    REQUIRE(err == EAHCM_SUCCESS);
    REQUIRE(written == blob_cpp.size());
    blob_c.resize(written);
    REQUIRE(blob_c == blob_cpp);

    eahcm_aead_destroy(c_ctx);
}

// =========================================================================
// Negative Tests: C API
// =========================================================================

TEST_CASE("C API handles NULL pointers safely", "[c_api][negative]") {
    uint8_t dummy[16] = {0};
    
    // Missing key
    REQUIRE(eahcm_aead_encrypt(nullptr, 32, dummy, 12, dummy, NULL, 0, dummy, 16, dummy, dummy) == EAHCM_ERROR_INVALID_ARGUMENT);
    
    // Missing required tags/ciphertexts but non-zero length
    REQUIRE(eahcm_aead_encrypt(dummy, 32, dummy, 12, dummy, NULL, 0, dummy, 16, nullptr, dummy) == EAHCM_ERROR_INVALID_ARGUMENT);
    REQUIRE(eahcm_aead_encrypt(dummy, 32, dummy, 12, dummy, NULL, 0, dummy, 16, dummy, nullptr) == EAHCM_ERROR_INVALID_ARGUMENT);
    
    // Context creation
    eahcm_aead_ctx* a_ctx = nullptr;
    REQUIRE(eahcm_aead_create(nullptr, dummy, 32, dummy, 12, nullptr, 0) == EAHCM_ERROR_INVALID_ARGUMENT);
    REQUIRE(eahcm_aead_create(&a_ctx, nullptr, 32, dummy, 12, nullptr, 0) == EAHCM_ERROR_INVALID_ARGUMENT);
}

TEST_CASE("C API translates exceptions to EAHCM_ERROR_AUTHENTICATION", "[c_api][negative]") {
    const auto key    = make_bytes(32, 0x11);
    const auto enonce = make_bytes(12, 0x22);
    const auto cnonce = make_bytes(12, 0x33);
    const auto pt     = make_bytes(16, 0x44);

    std::vector<uint8_t> ct(16);
    std::vector<uint8_t> tag(16);
    
    eahcm_aead_encrypt(key.data(), key.size(), enonce.data(), enonce.size(), cnonce.data(), nullptr, 0, pt.data(), pt.size(), ct.data(), tag.data());

    // Corrupt tag
    tag[0] ^= 0xFF;

    std::vector<uint8_t> dec(16, 0x00);
    eahcm_error_t err = eahcm_aead_decrypt(
        key.data(), key.size(),
        enonce.data(), enonce.size(),
        cnonce.data(),
        nullptr, 0,
        ct.data(), ct.size(),
        tag.data(),
        dec.data()
    );

    // Authentication failure expected
    REQUIRE(err == EAHCM_ERROR_AUTHENTICATION);
    
    // Buffer should not leak plaintext on failure (though C++ zeroisation handles the internal copy, 
    // our wrapper does not copy to `dec` if an exception occurred before std::copy).
    REQUIRE(dec == std::vector<uint8_t>(16, 0x00));
}

TEST_CASE("C API seal size validation", "[c_api][negative]") {
    const auto key    = make_bytes(32, 0x11);
    const auto enonce = make_bytes(12, 0x22);
    const auto cnonce = make_bytes(12, 0x33);
    const auto pt     = make_bytes(16, 0x44);

    eahcm_aead_ctx* ctx = nullptr;
    eahcm_aead_create(&ctx, key.data(), key.size(), enonce.data(), enonce.size(), nullptr, 0);

    size_t written = 0;
    std::vector<uint8_t> blob(eahcm_aead_sealed_size(pt.size()) - 1); // 1 byte too small

    eahcm_error_t err = eahcm_aead_seal(ctx, cnonce.data(), nullptr, 0, pt.data(), pt.size(), blob.data(), blob.size(), &written);
    REQUIRE(err == EAHCM_ERROR_BUFFER_TOO_SMALL);
    
    eahcm_aead_destroy(ctx);
}
