# Examples CMakeLists.txt
cmake_minimum_required(VERSION 3.20)

add_executable(example_keystream example_keystream.cpp)
target_link_libraries(example_keystream PRIVATE EAHCM::eahcm)

add_executable(example_state_export example_state_export.cpp)
target_link_libraries(example_state_export PRIVATE EAHCM::eahcm)

add_executable(example_determinism example_determinism.cpp)
target_link_libraries(example_determinism PRIVATE EAHCM::eahcm)
