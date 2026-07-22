// SPDX-License-Identifier: MIT
// test_cipher.cpp — Tests for the high-level Cipher API.

#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>
#include <thread>
#include "eahcm/cipher.hpp"

using namespace eahcm;

static std::vector<std::uint8_t> make_key(const char* s) {
    return std::vector<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s),
        reinterpret_cast<const std::uint8_t*>(s) + std::strlen(s));
}

static std::vector<std::uint8_t> make_nonce() {
    return std::vector<std::uint8_t>(12, 0x01);
}

TEST_CASE("Cipher: basic construction and generation", "[cipher]") {
    auto key = make_key("test-cipher-key");
    auto nonce = make_nonce();
    Cipher c(key, nonce);

    auto output = c.generate(64);
    REQUIRE(output.size() == 64);
    // Output should not be all zeros
    bool all_zero = true;
    for (auto b : output) if (b != 0) { all_zero = false; break; }
    REQUIRE_FALSE(all_zero);
}

TEST_CASE("Cipher: deterministic keystream", "[cipher]") {
    auto key = make_key("determinism-test");
    auto nonce = make_nonce();

    Cipher c1(key, nonce);
    Cipher c2(key, nonce);

    auto out1 = c1.generate(256);
    auto out2 = c2.generate(256);
    REQUIRE(out1 == out2);
}

TEST_CASE("Cipher: reset reproduces keystream", "[cipher]") {
    auto key = make_key("reset-test-key");
    auto nonce = make_nonce();

    Cipher c(key, nonce);
    auto first = c.generate(128);
    c.reset();
    auto second = c.generate(128);
    REQUIRE(first == second);
}

TEST_CASE("Cipher: reseed changes keystream", "[cipher]") {
    auto key1 = make_key("key-one");
    auto key2 = make_key("key-two");
    auto nonce = make_nonce();

    Cipher c(key1, nonce);
    auto out1 = c.generate(64);

    c.reseed(key2, nonce);
    auto out2 = c.generate(64);
    REQUIRE(out1 != out2);
}

TEST_CASE("Cipher: empty key throws", "[cipher]") {
    std::vector<std::uint8_t> empty;
    auto nonce = make_nonce();
    REQUIRE_THROWS_AS(Cipher(empty, nonce), KeyError);
}

TEST_CASE("Cipher: move semantics", "[cipher]") {
    auto key = make_key("move-test");
    auto nonce = make_nonce();

    Cipher c1(key, nonce);
    auto w1 = c1.next();

    Cipher c2(std::move(c1));
    auto w2 = c2.next();
    // After move, c2 should produce subsequent keystream
    REQUIRE(w1 != w2); // Different steps
}

TEST_CASE("Cipher: export/import state binary", "[cipher]") {
    auto key = make_key("export-test");
    auto nonce = make_nonce();

    Cipher c3(key, nonce);
    (void)c3.generate(100);
    auto snap = c3.export_state();
    auto w_snap = c3.next();

    Cipher c4(key, nonce);
    c4.import_state(snap);
    auto w_restored = c4.next();
    REQUIRE(w_snap == w_restored);
}

TEST_CASE("Cipher: thread safety (independent instances)", "[cipher][threads]") {
    const int N = 4;
    const int STEPS = 1000;

    auto key = make_key("thread-safety-test");
    auto nonce = make_nonce();

    // Generate reference output
    Cipher ref(key, nonce);
    std::vector<std::uint64_t> reference(STEPS);
    for (int i = 0; i < STEPS; ++i) {
        reference[i] = ref.next();
    }

    // Run N threads, each with its own cipher, verify identical output
    std::vector<std::vector<std::uint64_t>> results(N, std::vector<std::uint64_t>(STEPS));
    std::vector<std::thread> threads;
    for (int t = 0; t < N; ++t) {
        threads.emplace_back([&, t]() {
            Cipher c(key, nonce);
            for (int i = 0; i < STEPS; ++i) {
                results[t][i] = c.next();
            }
        });
    }
    for (auto& th : threads) th.join();

    for (int t = 0; t < N; ++t) {
        REQUIRE(results[t] == reference);
    }
}
