#!/bin/bash

echo "Setting up C++ AI Development Environment with ChatGPT Integration..."

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install required dependencies
echo "Installing dependencies..."
sudo apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libssl-dev \
    pkg-config

# Check if CURL is installed
if ! pkg-config --exists libcurl; then
    echo "Error: CURL library not found. Please install libcurl4-openssl-dev"
    exit 1
fi

echo "Dependencies installed successfully!"
echo ""
echo "To get your OpenAI API key:"
echo "1. Go to https://platform.openai.com/api-keys"
echo "2. Create a new API key"
echo "3. Copy the key and use it in the ChatGPT Integration tool"
echo ""
echo "Build the project with: ./build.sh"
echo "Run the program with: cd build && ./main"