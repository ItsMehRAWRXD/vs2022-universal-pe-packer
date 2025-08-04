#!/bin/bash

echo "Building VS2022Encryptor..."

# Create build directory
mkdir -p build

# Compile with g++
g++ -std=c++17 -o build/VS2022Encryptor main.cpp

if [ $? -eq 0 ]; then
    echo "Build successful! Executable created at build/VS2022Encryptor"
    echo "To run: ./build/VS2022Encryptor"
else
    echo "Build failed!"
    exit 1
fi