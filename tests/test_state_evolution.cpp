// SPDX-License-Identifier: MIT
// test_state_evolution.cpp — Reference vector validation for state step().
// Loads state_evolution.json, param_drift_vectors.json, extraction_vectors.json
// and verifies bit-exact match against the C++ implementation.

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <cstdint>
#include "eahcm/state.hpp"
#include "eahcm/constants.hpp"

using json = nlohmann::json;
using namespace eahcm;

static json load_json(const std::string& filename) {
    std::string path = std::string(EAHCM_VECTOR_DIR) + "/" + filename;
    std::ifstream f(path);
    REQUIRE(f.is_open());
    json j;
    f >> j;
    return j;
}

// =========================================================================
// State Evolution: bit-exact step-by-step validation
// =========================================================================

TEST_CASE("State evolution: SE-001 canonical 10 steps", "[state][vectors]") {
    auto data = load_json("state_evolution.json");
    auto& vectors = data["vectors"];

    for (auto& vec : vectors) {
        auto& seed = vec["initial_seed"];
        auto& trajectory = vec["trajectory"];
        std::string id = vec["id"];

        SECTION(id) {
            State s = make_state(
                seed["x"].get<std::uint32_t>(),
                seed["y"].get<std::uint32_t>(),
                seed["z"].get<std::uint32_t>(),
                seed["w"].get<std::uint32_t>(),
                seed["alpha"].get<std::uint32_t>(),
                seed["gamma"].get<std::uint32_t>(),
                seed["mu"].get<std::uint32_t>(),
                seed["sigma"].get<std::uint32_t>()
            );

            // Verify step 0 (initial state after clamping)
            auto& t0 = trajectory[0];
            REQUIRE(s.x == t0["x"].get<std::uint32_t>());
            REQUIRE(s.y == t0["y"].get<std::uint32_t>());
            REQUIRE(s.z == t0["z"].get<std::uint32_t>());
            REQUIRE(s.w == t0["w"].get<std::uint32_t>());
            REQUIRE(s.alpha == t0["alpha"].get<std::uint32_t>());
            REQUIRE(s.gamma == t0["gamma"].get<std::uint32_t>());
            REQUIRE(s.mu == t0["mu"].get<std::uint32_t>());
            REQUIRE(s.sigma == t0["sigma"].get<std::uint32_t>());
            REQUIRE(s.counter == t0["counter"].get<std::uint32_t>());

            // Verify extraction at step 0
            REQUIRE(extract(s) == t0["extract"].get<std::uint64_t>());

            // Step through trajectory
            int num_steps = vec["num_steps"].get<int>();
            for (int i = 1; i <= num_steps; ++i) {
                step(s);
                auto& ti = trajectory[i];
                INFO("Step " << i << " of " << id);
                REQUIRE(s.x == ti["x"].get<std::uint32_t>());
                REQUIRE(s.y == ti["y"].get<std::uint32_t>());
                REQUIRE(s.z == ti["z"].get<std::uint32_t>());
                REQUIRE(s.w == ti["w"].get<std::uint32_t>());
                REQUIRE(s.alpha == ti["alpha"].get<std::uint32_t>());
                REQUIRE(s.gamma == ti["gamma"].get<std::uint32_t>());
                REQUIRE(s.mu == ti["mu"].get<std::uint32_t>());
                REQUIRE(s.sigma == ti["sigma"].get<std::uint32_t>());
                REQUIRE(s.counter == ti["counter"].get<std::uint32_t>());
                REQUIRE(extract(s) == ti["extract"].get<std::uint64_t>());
            }
        }
    }
}

// =========================================================================
// Parameter drift: validate drift events at correct boundaries
// =========================================================================

TEST_CASE("Parameter drift: PD-001 drift events", "[drift][vectors]") {
    auto data = load_json("param_drift_vectors.json");
    auto& vec = data["vectors"][0];
    auto& seed = vec["initial_seed"];

    State s = make_state(
        seed["x"].get<std::uint32_t>(),
        seed["y"].get<std::uint32_t>(),
        seed["z"].get<std::uint32_t>(),
        seed["w"].get<std::uint32_t>(),
        seed["alpha"].get<std::uint32_t>(),
        seed["gamma"].get<std::uint32_t>(),
        seed["mu"].get<std::uint32_t>(),
        seed["sigma"].get<std::uint32_t>()
    );

    auto& events = vec["drift_events"];
    std::size_t event_idx = 0;
    std::uint32_t prev_alpha = s.alpha;

    for (int i = 1; i <= 200; ++i) {
        step(s);
        if (s.alpha != prev_alpha) {
            REQUIRE(event_idx < events.size());
            auto& ev = events[event_idx];
            INFO("Drift event at step " << i);
            REQUIRE(i == ev["step"].get<int>());
            REQUIRE(s.counter == ev["counter"].get<std::uint32_t>());
            REQUIRE(s.alpha == ev["new_alpha"].get<std::uint32_t>());
            REQUIRE(s.gamma == ev["new_gamma"].get<std::uint32_t>());
            REQUIRE(s.mu == ev["new_mu"].get<std::uint32_t>());
            REQUIRE(s.sigma == ev["new_sigma"].get<std::uint32_t>());
            event_idx++;
        }
        prev_alpha = s.alpha;
    }

    REQUIRE(event_idx == events.size());
}

// =========================================================================
// Extraction: validate against extraction_vectors.json
// =========================================================================

TEST_CASE("Extraction: EX-001 first 100 steps", "[extraction][vectors]") {
    auto data = load_json("extraction_vectors.json");
    auto& vec = data["vectors"][0];
    auto& records = vec["records"];

    // Use SE-001 canonical seed (same seed used by extraction vectors)
    State s = make_state(
        0x12345678u, 0x9ABCDEF0u, 0x13572468u, 0xACEBDFACu,
        0xF0000000u, 0xF1000000u, 0xF2000000u, 0xF3000000u
    );

    for (auto& rec : records) {
        int step_num = rec["step"].get<int>();
        step(s);

        INFO("Extraction at step " << step_num);
        REQUIRE(s.x == rec["x"].get<std::uint32_t>());
        REQUIRE(s.y == rec["y"].get<std::uint32_t>());
        REQUIRE(s.z == rec["z"].get<std::uint32_t>());
        REQUIRE(s.w == rec["w"].get<std::uint32_t>());
        REQUIRE(extract(s) == rec["extract"].get<std::uint64_t>());
    }
}

// =========================================================================
// Determinism: identical seeds produce identical trajectories
// =========================================================================

TEST_CASE("Determinism: identical seeds -> identical output", "[determinism]") {
    State sa = make_state(
        0xDEADBEEFu, 0x13371337u, 0xCAFEBABEu, 0xBAADF00Du,
        0xF5000000u, 0xF6000000u, 0xF7000000u, 0xF8000000u
    );
    State sb = sa;

    for (int i = 0; i < 1000; ++i) {
        step(sa);
        step(sb);
        REQUIRE(sa == sb);
        REQUIRE(extract(sa) == extract(sb));
    }
}

// =========================================================================
// Sensitivity: 1-bit difference should diverge
// =========================================================================

TEST_CASE("Sensitivity: 1-bit initial difference diverges", "[sensitivity]") {
    State sa = make_state(
        0x12345678u, 0x9ABCDEF0u, 0x13572468u, 0xACEBDFACu,
        0xF0000000u, 0xF1000000u, 0xF2000000u, 0xF3000000u
    );
    State sb = make_state(
        0x12345679u, 0x9ABCDEF0u, 0x13572468u, 0xACEBDFACu,
        0xF0000000u, 0xF1000000u, 0xF2000000u, 0xF3000000u
    );

    for (int i = 0; i < 10; ++i) {
        step(sa);
        step(sb);
    }

    REQUIRE(sa != sb);
}
