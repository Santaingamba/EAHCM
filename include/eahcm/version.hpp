// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EAHCM Authors
//
// version.hpp — Semantic versioning for the EAHCM library.

#ifndef EAHCM_VERSION_HPP
#define EAHCM_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace eahcm {

/// Major version — incremented on breaking API changes.
inline constexpr int VERSION_MAJOR = 1;

/// Minor version — incremented on backward-compatible feature additions.
inline constexpr int VERSION_MINOR = 0;

/// Patch version — incremented on backward-compatible bug fixes.
inline constexpr int VERSION_PATCH = 0;

/// Full version string.
inline constexpr std::string_view VERSION_STRING = "1.0.0";

/// ABI version for shared library compatibility.
inline constexpr int ABI_VERSION = 1;

/// Serialization format version (for state import/export).
inline constexpr std::uint32_t SERIALIZATION_VERSION = 1;

/// Returns the version string at compile time.
[[nodiscard]] constexpr std::string_view version() noexcept {
    return VERSION_STRING;
}

} // namespace eahcm

#endif // EAHCM_VERSION_HPP
