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
# Example (Google Benchmark):
#   add_executable(bench_throughput bench_throughput.cpp)
#   target_link_libraries(bench_throughput PRIVATE EAHCM::eahcm benchmark::benchmark)

# No benchmark targets yet — this file exists so that EAHCM_BUILD_BENCHMARKS=ON
# does not produce a CMake error.
