// SPDX-License-Identifier: MIT
// example_determinism.cpp — Verify deterministic keystream generation.

#include <iostream>
#include <iomanip>
#include <cassert>
#include "eahcm/cipher.hpp"

int main() {
    const std::uint8_t key[] = "determinism-verification-key!!!";
    const std::uint8_t nonce[] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55};

    // Create two independent ciphers with identical material
    eahcm::Cipher c1(key, nonce);
    eahcm::Cipher c2(key, nonce);

    std::cout << "Verifying determinism over 1000 steps...\n";
    bool all_match = true;
    for (int i = 0; i < 1000; ++i) {
        auto w1 = c1.next();
        auto w2 = c2.next();
        if (w1 != w2) {
            std::cout << "MISMATCH at step " << i << "!\n";
            all_match = false;
            break;
        }
    }

    if (all_match) {
        std::cout << "All 1000 keystream words match. EAHCM is fully deterministic.\n";
    }

    // Verify reset
    c1.reset();
    eahcm::Cipher c3(key, nonce);
    std::cout << "\nVerifying reset produces identical keystream...\n";
    for (int i = 0; i < 100; ++i) {
        assert(c1.next() == c3.next());
    }
    std::cout << "Reset verification passed.\n";

    return 0;
}
