# SPDX-License-Identifier: MIT
# tests/CMakeLists.txt — EAHCM Catch2 test suite.
#
# Fetches Catch2 and nlohmann/json via FetchContent, then defines one
# executable per test category.  All executables are registered with CTest.
#
# Enabled when: EAHCM_BUILD_TESTS=ON (default)

include(FetchContent)

# ---- Fetch Catch2 ----
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.5.2
)
FetchContent_MakeAvailable(Catch2)

# ---- Fetch nlohmann/json for test vector parsing ----
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# ---- Reference vector directory (authoritative JSON files) ----
set(VECTOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vectors")

# ---- Test: Core primitives (L, F, R, rol32) ----
add_executable(test_primitives test_primitives.cpp)
target_link_libraries(test_primitives PRIVATE EAHCM::eahcm Catch2::Catch2WithMain)
target_compile_definitions(test_primitives PRIVATE
    EAHCM_VECTOR_DIR="${VECTOR_DIR}"
)
add_test(NAME test_primitives COMMAND test_primitives)

# ---- Test: State evolution (reference vectors) ----
add_executable(test_state_evolution test_state_evolution.cpp test_helpers.hpp)
target_link_libraries(test_state_evolution PRIVATE EAHCM::eahcm Catch2::Catch2WithMain nlohmann_json::nlohmann_json)
target_compile_definitions(test_state_evolution PRIVATE
    EAHCM_VECTOR_DIR="${VECTOR_DIR}"
)
add_test(NAME test_state_evolution COMMAND test_state_evolution)

# ---- Test: Key schedule (init vectors) ----
add_executable(test_key_schedule test_key_schedule.cpp test_helpers.hpp)
target_link_libraries(test_key_schedule PRIVATE EAHCM::eahcm Catch2::Catch2WithMain nlohmann_json::nlohmann_json)
target_compile_definitions(test_key_schedule PRIVATE
    EAHCM_VECTOR_DIR="${VECTOR_DIR}"
)
add_test(NAME test_key_schedule COMMAND test_key_schedule)

# ---- Test: Serialization ----
add_executable(test_serialization test_serialization.cpp)
target_link_libraries(test_serialization PRIVATE EAHCM::eahcm Catch2::Catch2WithMain)
add_test(NAME test_serialization COMMAND test_serialization)

# ---- Test: Cipher API ----
add_executable(test_cipher test_cipher.cpp)
target_link_libraries(test_cipher PRIVATE EAHCM::eahcm Catch2::Catch2WithMain)
add_test(NAME test_cipher COMMAND test_cipher)

# ---- Test: AEAD Construction (Stage 2) ----
add_executable(test_aead test_aead.cpp)
target_link_libraries(test_aead PRIVATE EAHCM::eahcm Catch2::Catch2WithMain OpenSSL::Crypto)
add_test(NAME test_aead COMMAND test_aead)

# ---- Test: C API Compilation (Stage 3) ----
add_executable(test_c_api test_c_api.c)
target_link_libraries(test_c_api PRIVATE EAHCM::eahcm)
add_test(NAME test_c_api COMMAND test_c_api)

# ---- Test: C API Functional vs C++ (Stage 3) ----
add_executable(test_c_api_functional test_c_api_functional.cpp)
target_link_libraries(test_c_api_functional PRIVATE EAHCM::eahcm Catch2::Catch2WithMain)
add_test(NAME test_c_api_functional COMMAND test_c_api_functional)
