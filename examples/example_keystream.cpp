// SPDX-License-Identifier: MIT
// example_keystream.cpp — Generate keystream bytes using EAHCM.

#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include "eahcm/cipher.hpp"

int main() {
    // Key and nonce (in production, derive from secure random source)
    const std::uint8_t key[] = "EAHCM-example-key-32-bytes!!!!!";
    const std::uint8_t nonce[] = {0,1,2,3,4,5,6,7,8,9,10,11};

    // Create cipher (performs key derivation + 256-step warmup)
    eahcm::Cipher cipher(key, nonce);

    // Generate 64 bytes of keystream
    auto keystream = cipher.generate(64);

    std::cout << "EAHCM Keystream (64 bytes):\n";
    for (std::size_t i = 0; i < keystream.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(keystream[i]);
        if ((i + 1) % 16 == 0) std::cout << '\n';
        else std::cout << ' ';
    }

    // Generate individual 64-bit words
    std::cout << "\nNext 8 keystream words (64-bit):\n";
    for (int i = 0; i < 8; ++i) {
        auto word = cipher.next();
        std::cout << "  [" << i << "] 0x" << std::hex << std::setw(16)
                  << std::setfill('0') << word << '\n';
    }

    return 0;
}
