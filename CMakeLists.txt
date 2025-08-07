cmake_minimum_required(VERSION 3.10)
project(CppAIEnvironment)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable debugging
set(CMAKE_BUILD_TYPE Debug)

# Add compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Set include directories globally
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add subdirectories for different modules
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(examples)

# Create main executable
add_executable(CppAIDevelopmentEnviroment src/main.cpp)
target_link_libraries(CppAIDevelopmentEnviroment cpp_lib)

# Set include directories for the main executable
target_include_directories(CppAIDevelopmentEnviroment PRIVATE ${CMAKE_SOURCE_DIR}/include)