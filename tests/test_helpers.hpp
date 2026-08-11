// SPDX-License-Identifier: MIT
// test_helpers.hpp — Shared test utilities for the EAHCM test suite.
//
// Provides common JSON loading and hex-to-bytes conversion functions
// used across multiple test files to avoid code duplication.

#pragma once
#ifndef EAHCM_TEST_HELPERS_HPP
#define EAHCM_TEST_HELPERS_HPP

#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

/// Load a JSON file from the EAHCM_VECTOR_DIR directory.
///
/// @param filename  The filename (relative to EAHCM_VECTOR_DIR).
/// @return          Parsed JSON object.
inline nlohmann::json load_json(const std::string &filename) {
  std::string path = std::string(EAHCM_VECTOR_DIR) + "/" + filename;
  std::ifstream f(path);
  REQUIRE(f.is_open());
  nlohmann::json j;
  f >> j;
  return j;
}

/// Convert a hex string (e.g. "DEADBEEF") to a byte vector.
///
/// @param hex  The hex string (must have even length, no prefix).
/// @return     Vector of decoded bytes.
inline std::vector<std::uint8_t> hex_to_bytes(const std::string &hex) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    auto byte_str = hex.substr(i, 2);
    bytes.push_back(
        static_cast<std::uint8_t>(std::stoul(byte_str, nullptr, 16)));
  }
  return bytes;
}

#endif // EAHCM_TEST_HELPERS_HPP
