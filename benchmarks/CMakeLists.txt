# Benchmarks CMakeLists.txt
# Placeholder for future performance benchmarks.
#
# To add a benchmark:
#   1. Create a .cpp file in this directory
#   2. Link against EAHCM::eahcm (and optionally a benchmarking framework)
#   3. Enable with: cmake -DEAHCM_BUILD_BENCHMARKS=ON
#
# Example:
#   add_executable(bench_throughput bench_throughput.cpp)
#   target_link_libraries(bench_throughput PRIVATE EAHCM::eahcm)

cmake_minimum_required(VERSION 3.20)

# No benchmark targets yet — this file exists so that
# EAHCM_BUILD_BENCHMARKS=ON does not cause a CMake error.
