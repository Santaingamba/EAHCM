/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 EAHCM Authors */
/*
 * test_c_api.c — Compilation and sanity test for the C ABI.
 *
 * This file is intentionally compiled with a C compiler, NOT a C++ compiler,
 * to ensure that eahcm.h contains no C++ dependencies and is fully valid C.
 */

#include "eahcm/eahcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal assert for C testing */
#define C_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while(0)

int main(void) {
    const uint8_t key[32] = { 0xAB }; /* minimal key */
    const uint8_t nonce[12] = { 0x01 };
    
    printf("EAHCM C API Version: %08x\n", eahcm_api_version());
    
    /* 1. Test stateless AEAD errors */
    {
        uint8_t out_ct[16] = {0};
        uint8_t out_tag[16] = {0};
        eahcm_error_t err = eahcm_aead_encrypt(
            NULL, 32, /* NULL key should fail */
            nonce, 12,
            nonce, /* cnonce */
            NULL, 0,
            NULL, 0,
            out_ct, out_tag
        );
        C_ASSERT(err == EAHCM_ERROR_INVALID_ARGUMENT);
    }
    
    /* 2. Test context lifecycle (Cipher) */
    {
        eahcm_cipher_ctx* c_ctx = NULL;
        eahcm_error_t err = eahcm_cipher_create(&c_ctx, key, 32, nonce, 12, NULL, 0);
        C_ASSERT(err == EAHCM_SUCCESS);
        C_ASSERT(c_ctx != NULL);
        
        uint8_t ks[16] = {0};
        err = eahcm_cipher_generate(c_ctx, ks, 16);
        C_ASSERT(err == EAHCM_SUCCESS);
        
        eahcm_cipher_destroy(c_ctx);
    }
    
    /* 3. Test context lifecycle (AEAD) */
    {
        eahcm_aead_ctx* a_ctx = NULL;
        eahcm_error_t err = eahcm_aead_create(&a_ctx, key, 32, nonce, 12, NULL, 0);
        C_ASSERT(err == EAHCM_SUCCESS);
        C_ASSERT(a_ctx != NULL);
        
        const uint8_t pt[5] = "test";
        uint8_t ct[5] = {0};
        uint8_t tag[16] = {0};
        
        err = eahcm_aead_encrypt_message(a_ctx, nonce, NULL, 0, pt, 4, ct, tag);
        if (err != EAHCM_SUCCESS) {
            fprintf(stderr, "eahcm_aead_encrypt_message failed: %d\n", err);
            exit(1);
        }
        
        eahcm_aead_reset(a_ctx);
        
        uint8_t dec[5] = {0};
        err = eahcm_aead_decrypt_message(a_ctx, nonce, NULL, 0, ct, 4, tag, dec);
        if (err != EAHCM_SUCCESS) {
            fprintf(stderr, "eahcm_aead_decrypt_message failed: %d\n", err);
            exit(1);
        }
        C_ASSERT(err == EAHCM_SUCCESS);
        C_ASSERT(memcmp(pt, dec, 4) == 0);
        
        eahcm_aead_destroy(a_ctx);
    }
    
    printf("C API compilation and sanity test passed.\n");
    return 0;
}
