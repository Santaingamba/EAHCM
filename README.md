# EAHCM — Official C++ Reference Implementation

[![Build](https://github.com/eahcm/eahcm/actions/workflows/ci.yml/badge.svg)](https://github.com/eahcm/eahcm/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/)

Production-quality C++20 reference implementation of the **EAHCM 4D Chaotic Cipher**, accompanying the research publication.

## Features

- **Bit-exact** reproduction of the Python reference implementation
- **Modern C++20**: concepts, `std::span`, `std::array`, `[[nodiscard]]`, RAII
- **Cross-platform**: Windows, Linux, macOS (GCC, Clang, MSVC)
- **Secure**: constant-time operations, secure memory zeroisation, no UB
- **Installable**: CMake `find_package(EAHCM)`, FetchContent, vcpkg, Conan
- **Tested**: Catch2 test suite with reference vector validation
- **Documented**: Doxygen API documentation

## Quick Start

### Build from Source

```bash
git clone https://github.com/eahcm/eahcm.git
cd eahcm
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

### Usage

```cpp
#include <eahcm/cipher.hpp>

int main() {
    const uint8_t key[] = "my-secret-key-32-bytes-long!!!!";
    const uint8_t nonce[] = {0,1,2,3,4,5,6,7,8,9,10,11};

    eahcm::Cipher cipher(key, nonce);
    auto keystream = cipher.generate(64);  // 64 bytes of keystream

    cipher.reset();  // Reproduce the same keystream
}
```

### CMake Integration

#### FetchContent
```cmake
include(FetchContent)
FetchContent_Declare(EAHCM
    GIT_REPOSITORY https://github.com/eahcm/eahcm.git
    GIT_TAG v1.0.0
)
FetchContent_MakeAvailable(EAHCM)

target_link_libraries(my_app PRIVATE EAHCM::eahcm)
```

#### find_package (after install)
```cmake
find_package(EAHCM REQUIRED)
target_link_libraries(my_app PRIVATE EAHCM::eahcm)
```

## Architecture

```
EAHCM/
├── include/eahcm/     # Public headers
│   ├── eahcm.hpp      # Umbrella header
│   ├── cipher.hpp     # High-level Cipher API
│   ├── state.hpp      # State machine (step, drift, extract)
│   ├── arithmetic.hpp # L(), F(), R() — frozen primitives
│   ├── key_schedule.hpp # HKDF-SHA3-256 key derivation
│   └── ...
├── src/               # Implementation files
├── tests/             # Catch2 test suite
│   └── vectors/       # Reference vectors (authoritative)
├── examples/          # Usage examples
├── benchmarks/        # Google Benchmark (optional)
├── docs/              # Doxygen configuration
└── cmake/             # CMake package config
```

## Mathematical Primitives

All primitives are **frozen** and match the Python reference exactly:

| Primitive | Description | Reference |
|-----------|-------------|-----------|
| `L(v, p)` | Integer Logistic Driver | §3.1 |
| `F(v)` | Branchless Tent Map | §3.2 |
| `R(w)` | SHA-256-inspired Bit-Mixer | §3.3 |

## Dependencies

- **C++20 compiler**: GCC 11+, Clang 14+, MSVC 19.29+
- **OpenSSL 1.1.1+**: For HMAC-SHA3-256 key derivation
- **Catch2 3.x**: Test framework (fetched automatically)
- **nlohmann/json 3.x**: Test vector parsing (fetched automatically)

## License

MIT License — see [LICENSE](LICENSE).
