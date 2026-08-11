/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 EAHCM Authors */
/*
 * example_c_api.c — Demonstration of using EAHCM securely via the C ABI.
 */

#include "eahcm/eahcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("--- EAHCM C API Example ---\n");
    printf("API Version: %08x\n\n", eahcm_api_version());

    /* 1. Key material (in practice, generate this securely) */
    const uint8_t user_key[32] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
                                   0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                                   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
                                   0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };
    
    /* EAHCM Initialization Nonce (12 bytes recommended for HKDF) */
    const uint8_t enonce[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    
    /* ChaCha20-Poly1305 Nonce (12 bytes mandatory per RFC 8439) */
    const uint8_t cnonce[12] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44 };

    /* 2. Message to encrypt */
    const char* message = "Top secret chaotic payload.";
    const size_t message_len = strlen(message);
    
    /* AAD (Additional Authenticated Data) */
    const char* aad = "header_info";
    const size_t aad_len = strlen(aad);

    printf("Original message: %s\n", message);
    print_hex("Original bytes", (const uint8_t*)message, message_len);
    printf("\n");

    /* 3. Create context */
    eahcm_aead_ctx* ctx = NULL;
    eahcm_error_t err = eahcm_aead_create(&ctx, user_key, sizeof(user_key), enonce, sizeof(enonce), NULL, 0);
    if (err != EAHCM_SUCCESS) {
        fprintf(stderr, "Failed to create context: %d\n", err);
        return 1;
    }

    /* 4. Encrypt */
    uint8_t* ciphertext = (uint8_t*)malloc(message_len);
    uint8_t tag[16] = {0};
    
    err = eahcm_aead_encrypt_message(
        ctx,
        cnonce,
        (const uint8_t*)aad, aad_len,
        (const uint8_t*)message, message_len,
        ciphertext,
        tag
    );
    
    if (err != EAHCM_SUCCESS) {
        fprintf(stderr, "Encryption failed: %d\n", err);
        eahcm_aead_destroy(ctx);
        free(ciphertext);
        return 1;
    }

    print_hex("Ciphertext", ciphertext, message_len);
    print_hex("Poly1305 Tag", tag, sizeof(tag));
    printf("\n");

    /* 5. Decrypt */
    /* Context state advances on encryption. To decrypt, we must reset the context,
       or simply create a new one to simulate the receiver side. */
    eahcm_aead_reset(ctx);
    
    uint8_t* decrypted = (uint8_t*)malloc(message_len);
    
    err = eahcm_aead_decrypt_message(
        ctx,
        cnonce,
        (const uint8_t*)aad, aad_len,
        ciphertext, message_len,
        tag,
        decrypted
    );

    if (err != EAHCM_SUCCESS) {
        fprintf(stderr, "Decryption failed (Authentication error?): %d\n", err);
        eahcm_aead_destroy(ctx);
        free(ciphertext);
        free(decrypted);
        return 1;
    }

    printf("Decrypted successfully.\n");
    print_hex("Decrypted bytes", decrypted, message_len);
    
    /* Null-terminate for printing (safe because we control the test) */
    char* dec_str = (char*)malloc(message_len + 1);
    memcpy(dec_str, decrypted, message_len);
    dec_str[message_len] = '\0';
    printf("Decrypted string: %s\n", dec_str);

    /* 6. Cleanup */
    free(dec_str);
    free(decrypted);
    free(ciphertext);
    eahcm_aead_destroy(ctx);

    return 0;
}
