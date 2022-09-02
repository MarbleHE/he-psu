cmake_minimum_required(VERSION 3.16)

project(fhe_psu)

# Require C++17
set(CMAKE_CXX_STANDARD 17)

# SEAL's BFV implementation is used
find_package(SEAL 4.0 REQUIRED)

## Private Set Union Library Target
add_library(psu
    src/psu.cpp
)
target_include_directories(psu PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include")
target_link_libraries(psu PUBLIC SEAL::seal)

## Example Target
add_executable(example 
    example.cpp
    )
    target_link_libraries(example psu)


