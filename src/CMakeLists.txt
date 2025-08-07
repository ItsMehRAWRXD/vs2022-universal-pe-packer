# Source directory CMakeLists.txt
set(SOURCES
    main.cpp
    utils.cpp
    calculator.cpp
    game.cpp
    assembler.cpp
)

# Create library from source files
add_library(cpp_lib ${SOURCES})

# Set include directories
target_include_directories(cpp_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)