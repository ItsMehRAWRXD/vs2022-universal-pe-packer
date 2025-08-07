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

# Add subdirectories for different modules
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(examples)

# Create main executable
add_executable(main src/main.cpp)
target_link_libraries(main cpp_lib)