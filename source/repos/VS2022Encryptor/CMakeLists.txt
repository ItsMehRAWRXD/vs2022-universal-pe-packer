cmake_minimum_required(VERSION 3.10)
project(VS2022Encryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(VS2022Encryptor main.cpp)

# Set output directory
set_target_properties(VS2022Encryptor PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)