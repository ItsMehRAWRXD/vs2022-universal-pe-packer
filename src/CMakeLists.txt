# Source directory CMakeLists.txt
set(SOURCES
    main.cpp
    utils.cpp
    calculator.cpp
    game.cpp
    assembler.cpp
    chatgpt.cpp
)

# Create library from source files
add_library(cpp_lib ${SOURCES})

# Set include directories for the library
target_include_directories(cpp_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Set include directories for all source files in this directory
target_include_directories(cpp_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})