# SPDX-License-Identifier: MIT
# benchmarks/CMakeLists.txt — EAHCM performance benchmarks.
#
# Placeholder for future throughput and latency benchmarks.
#
# Enabled when: EAHCM_BUILD_BENCHMARKS=ON (default: OFF)
#
# To add a benchmark:
#   1. Create a .cpp file in this directory.
#   2. Link against EAHCM::eahcm (and optionally a benchmarking framework,
#      e.g. Google Benchmark via FetchContent).
#   3. Enable with: cmake -DEAHCM_BUILD_BENCHMARKS=ON ..
#
include(FetchContent)

FetchContent_Declare(
    benchmark
    URL https://github.com/google/benchmark/archive/refs/tags/v1.9.1.tar.gz
    URL_HASH SHA256=32131c08ee31eeff2c8968d7e874f3cb648034377dfc32a4c377fa8796d84981
)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark tests" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Disable benchmark install" FORCE)
FetchContent_MakeAvailable(benchmark)

add_executable(bench_scalar bench_scalar.cpp)
target_link_libraries(bench_scalar PRIVATE benchmark::benchmark benchmark::benchmark_main EAHCM::eahcm OpenSSL::Crypto)

add_executable(bench_simd bench_simd.cpp)
target_link_libraries(bench_simd PRIVATE benchmark::benchmark benchmark::benchmark_main EAHCM::eahcm)
if (MSVC)
    target_compile_options(bench_simd PRIVATE /arch:AVX2)
else()
    target_compile_options(bench_simd PRIVATE -mavx2)
endif()

# Add custom run_benchmarks target for convenience
add_custom_target(run_benchmarks
    COMMAND bench_scalar --benchmark_out=scalar_baseline.json --benchmark_out_format=json
    DEPENDS bench_scalar
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
