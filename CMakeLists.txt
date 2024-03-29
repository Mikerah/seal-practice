cmake_minimum_required(VERSION 3.10)

# Set the project name
project(seal-practice)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Locate the SEAL library
find_package(SEAL CONFIG REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

# Add an executable
add_executable(main ../example_runner.cpp)

target_sources(main PRIVATE
    ../simple_arithmetic.cpp
    ../simple_floating_point.cpp
    ../simple_arrays.cpp
    ../simple_conditional_select.cpp
    ../ckks_sort.cpp
)

# Link the executable to the SEAL library.
target_link_libraries(main PRIVATE SEAL::seal)
