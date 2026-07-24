// SPDX-License-Identifier: MIT
// test_key_schedule.cpp — Validate HKDF key schedule against init_vectors.json.

#include "eahcm/key_schedule.hpp"
#include "eahcm/state.hpp"
#include "test_helpers.hpp"
#include <catch2/catch_test_macros.hpp>

using json = nlohmann::json;
using namespace eahcm;

TEST_CASE("Key schedule: init vectors validation", "[keyschedule][vectors]") {
  auto data = load_json("init_vectors.json");
  auto &vectors = data["vectors"];

  for (auto &vec : vectors) {
    std::string id = vec["id"];
    SECTION(id) {
      auto key_bytes = hex_to_bytes(vec["key_hex"].get<std::string>());
      auto nonce_bytes = hex_to_bytes(vec["nonce_hex"].get<std::string>());

      // Test pre-warmup parameters
      auto params = get_init_params(key_bytes, nonce_bytes);

      auto &pre = vec["pre_warmup"];
      INFO("Pre-warmup validation for " << id);
      REQUIRE(params.init_x == pre["init_x"].get<std::uint32_t>());
      REQUIRE(params.init_y == pre["init_y"].get<std::uint32_t>());
      REQUIRE(params.init_z == pre["init_z"].get<std::uint32_t>());
      REQUIRE(params.init_w == pre["init_w"].get<std::uint32_t>());
      REQUIRE(params.init_alpha == pre["init_alpha"].get<std::uint32_t>());
      REQUIRE(params.init_gamma == pre["init_gamma"].get<std::uint32_t>());
      REQUIRE(params.init_mu == pre["init_mu"].get<std::uint32_t>());
      REQUIRE(params.init_sigma == pre["init_sigma"].get<std::uint32_t>());

      // Test post-warmup state
      auto state = derive_state(key_bytes, nonce_bytes);

      auto &post = vec["post_warmup"];
      INFO("Post-warmup validation for " << id);
      REQUIRE(state.x == post["x"].get<std::uint32_t>());
      REQUIRE(state.y == post["y"].get<std::uint32_t>());
      REQUIRE(state.z == post["z"].get<std::uint32_t>());
      REQUIRE(state.w == post["w"].get<std::uint32_t>());
      REQUIRE(state.alpha == post["alpha"].get<std::uint32_t>());
      REQUIRE(state.gamma == post["gamma"].get<std::uint32_t>());
      REQUIRE(state.mu == post["mu"].get<std::uint32_t>());
      REQUIRE(state.sigma == post["sigma"].get<std::uint32_t>());
      REQUIRE(state.counter == post["counter"].get<std::uint32_t>());

      // Test extraction after warmup
      auto ext = extract(state);
      REQUIRE(ext == vec["post_warmup_extract"].get<std::uint64_t>());
    }
  }
}

TEST_CASE("Key schedule: empty key throws", "[keyschedule]") {
  std::vector<std::uint8_t> empty_key;
  std::vector<std::uint8_t> nonce(12, 0);
  REQUIRE_THROWS_AS(derive_state(empty_key, nonce), KeyError);
}

TEST_CASE("Key schedule: determinism", "[keyschedule]") {
  std::vector<std::uint8_t> key = {'t', 'e', 's', 't'};
  std::vector<std::uint8_t> nonce(12, 0x01);

  auto s1 = derive_state(key, nonce);
  auto s2 = derive_state(key, nonce);
  REQUIRE(s1 == s2);
}

TEST_CASE("Key schedule: different nonces diverge", "[keyschedule]") {
  std::vector<std::uint8_t> key = {'t', 'e', 's', 't'};
  std::vector<std::uint8_t> nonce_a(12, 0x01);
  std::vector<std::uint8_t> nonce_b(12, 0x02);

  auto sa = derive_state(key, nonce_a);
  auto sb = derive_state(key, nonce_b);
  REQUIRE(sa != sb);
}

TEST_CASE("Key schedule: counter == WARMUP_STEPS after init", "[keyschedule]") {
  std::vector<std::uint8_t> key = {'c', 'o', 'u', 'n', 't', 'e', 'r'};
  std::vector<std::uint8_t> nonce(12, 0);

  auto s = derive_state(key, nonce);
  REQUIRE(s.counter == WARMUP_STEPS);
}
