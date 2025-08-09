#!/bin/bash

echo "Building C++ AI Development Environment..."

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Configure with CMake
echo "Configuring project..."
cmake ..

# Build the project
echo "Building project..."
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Run the program with: ./build/main"
    echo "Or use: cd build && ./main"
else
    echo "Build failed!"
    exit 1
fi