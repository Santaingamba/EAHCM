# SPDX-License-Identifier: MIT
# examples/CMakeLists.txt — EAHCM usage examples.
#
# Enabled when: EAHCM_BUILD_EXAMPLES=ON (default)

add_executable(example_keystream example_keystream.cpp)
target_link_libraries(example_keystream PRIVATE EAHCM::eahcm)

add_executable(example_state_export example_state_export.cpp)
target_link_libraries(example_state_export PRIVATE EAHCM::eahcm)

add_executable(example_determinism example_determinism.cpp)
target_link_libraries(example_determinism PRIVATE EAHCM::eahcm)

add_executable(example_c_api example_c_api.c)
target_link_libraries(example_c_api PRIVATE EAHCM::eahcm)
