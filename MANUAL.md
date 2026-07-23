# EAHCM C++ Reference Implementation - Detailed Manual

## 1. Introduction
The EAHCM project is the official production-quality C++20 reference implementation of the **EAHCM 4D Chaotic Cipher**. It is designed to perfectly reproduce the behavior of the Python reference implementation while providing high performance, cross-platform compatibility, and an easy-to-use API suitable for integration into existing C++ projects.

---

## 2. Getting Started: How to Download & Configure

### Prerequisites
To build and use EAHCM, your environment must support the following:
* **C++20 Compiler:** GCC 11+, Clang 14+, or MSVC 19.29+
* **Build System:** CMake 3.15 or newer
* **Cryptography Dependency:** OpenSSL 1.1.1+ (used for HMAC-SHA3-256 during the Key Schedule phase)

### Downloading the Repository
You can obtain the source code by cloning the repository from GitHub:
```bash
git clone https://github.com/Santaingamba/EAHCM.git
cd EAHCM
```

### Configuration and Building
The project uses CMake for its build system. To configure and build the library, tests, and examples, follow these steps:

**Standard Build:**
```bash
# 1. Configure the project, setting the build type to Release for optimal performance
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 2. Compile the project
cmake --build build

# 3. (Optional) Run the test suite to ensure correctness
ctest --test-dir build
```

**CMake Integration (For Your Own Projects)**
To use EAHCM inside your own CMake project, you can use `FetchContent`:
```cmake
include(FetchContent)
FetchContent_Declare(EAHCM
    GIT_REPOSITORY https://github.com/Santaingamba/EAHCM.git
    GIT_TAG main
)
FetchContent_MakeAvailable(EAHCM)

# Link your application against the EAHCM library
target_link_libraries(my_app PRIVATE EAHCM::eahcm)
```

---

## 3. Core API Syntaxes and Detailed Usage

The central class you will interact with is `eahcm::Cipher`, located in `<eahcm/cipher.hpp>`.

### 3.1. Initialization (Inputs)
To initialize the cipher, you must provide a **Key** and a **Nonce**.
* **Key:** A standard byte array/vector. In production, this should be a cryptographically secure sequence of bytes.
* **Nonce:** (Number used once). Essential to ensure that identical keys produce different keystreams across different sessions or files.

**Example Setup:**
```cpp
#include <eahcm/cipher.hpp>
#include <cstdint>

// 32-byte key (256-bit)
const std::uint8_t key[] = "EAHCM-example-key-32-bytes!!!!!";

// 12-byte nonce (96-bit)
const std::uint8_t nonce[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

// Instantiate the cipher
// NOTE: The constructor automatically performs the key schedule 
// derivation and a 256-step warmup to achieve high chaos.
eahcm::Cipher cipher(key, nonce);
```

### 3.2. Generating Keystream (Outputs)
Once initialized, you can extract the pseudorandom keystream in different formats.

**Generating Byte Vectors (`generate`)**
If you need a specific number of bytes (e.g., to XOR against a plaintext block):
```cpp
// Generate a std::vector<uint8_t> containing 64 bytes of keystream
auto keystream_bytes = cipher.generate(64);
```

**Generating 64-bit Words (`next`)**
For high-performance applications where you want to process data in larger chunks, you can pull raw 64-bit unsigned integers directly from the cipher's state generator:
```cpp
// Generates the next 64-bit block of the keystream
std::uint64_t chaotic_word = cipher.next();
```

**Resetting the Cipher**
If you need to reproduce the exact same keystream from the beginning, use `reset()`:
```cpp
cipher.reset(); // Restores the internal state back to post-warmup
```

### 3.3. State Exporting and Importing
A highly advanced feature of EAHCM is the ability to export the exact internal parameters and variables of the chaotic system and resume execution later.

**Exporting State**
You can export the state as either binary data (for efficient storage) or JSON (for debugging or inter-language compatibility with Python):
```cpp
// Export as a binary vector (std::vector<uint8_t>)
auto binary_state = cipher.export_state();

// Export as a JSON formatted std::string
std::string json_state = cipher.export_state_json();
```

**Importing State**
To resume a cipher session precisely where it left off, instantiate a new Cipher with the original key and nonce, then call `import_state`:
```cpp
// 1. Create a fresh cipher instance using the same initial parameters
eahcm::Cipher new_cipher(key, nonce);

// 2. Overwrite the internal state using the previously saved binary state
new_cipher.import_state(binary_state);

// new_cipher will now produce the exact same sequence of bytes as the original cipher would have
```

---

## 4. Under the Hood: Mathematical Primitives
The internal architecture relies on strictly defined, frozen mathematical primitives that operate in constant-time.

* **`L(v, p)` Integer Logistic Driver**: Provides the core non-linear behavior based on the logistic map, adapted for finite integer fields.
* **`F(v)` Branchless Tent Map**: An auxiliary chaotic map designed without conditional branching to prevent side-channel timing attacks.
* **`R(w)` SHA-256-inspired Bit-Mixer**: Ensures high diffusion of bits across the 64-bit word, eliminating statistical biases.

---

## 5. Security & Best Practices
1. **Never Reuse Nonces**: Reusing a nonce with the same key breaks stream cipher security completely. Always use a unique nonce per stream/file.
2. **Key Derivation**: The EAHCM wrapper handles HKDF-SHA3-256 internally. Your provided key acts as Initial Keying Material (IKM).
3. **Memory Safety**: The implementation uses secure zeroisation (where supported) to wipe sensitive states when the `Cipher` object falls out of scope via RAII.

---
*For a deeper dive into the specific equations and cryptanalysis, refer to the accompanying scientific papers in the project's documentation folder.*
