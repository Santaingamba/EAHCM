// SPDX-License-Identifier: MIT
// example_state_export.cpp — Export and import cipher state.

#include <iostream>
#include <iomanip>
#include "eahcm/cipher.hpp"

int main() {
    const std::uint8_t key[] = "state-export-example-key-32byte";
    const std::uint8_t nonce[] = {0,1,2,3,4,5,6,7,8,9,10,11};

    eahcm::Cipher cipher(key, nonce);

    // Advance state
    for (int i = 0; i < 100; ++i) (void)cipher.next();

    // Export as JSON
    auto json = cipher.export_state_json();
    std::cout << "Exported state (JSON):\n" << json << "\n\n";

    // Export as binary
    auto binary = cipher.export_state();
    std::cout << "Exported state (binary, " << binary.size() << " bytes):\n";
    for (std::size_t i = 0; i < binary.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(binary[i]);
        if ((i + 1) % 16 == 0) std::cout << '\n';
        else std::cout << ' ';
    }
    std::cout << "\n\n";

    // Record next word
    auto word_before = cipher.next();
    std::cout << "Word after export: 0x" << std::hex << std::setw(16)
              << std::setfill('0') << word_before << '\n';

    // Import the saved state into a new cipher
    eahcm::Cipher cipher2(key, nonce);
    cipher2.import_state(binary);
    auto word_after = cipher2.next();
    std::cout << "Word after import: 0x" << std::hex << std::setw(16)
              << std::setfill('0') << word_after << '\n';

    std::cout << "\nMatch: " << (word_before == word_after ? "YES" : "NO") << '\n';

    return 0;
}
