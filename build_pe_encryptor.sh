#!/bin/bash

echo "Cross-Platform PE Encryptor - Build Script"
echo "=========================================="

# Check for required dependencies
echo "Checking dependencies..."

# Check for OpenSSL development package
if ! pkg-config --exists openssl; then
    echo "Error: OpenSSL development package not found."
    echo "Install with: sudo apt-get install libssl-dev"
    echo "Or: sudo yum install openssl-devel"
    exit 1
fi

# Check for g++
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ compiler not found."
    echo "Install with: sudo apt-get install build-essential"
    exit 1
fi

echo "✓ All dependencies found"

# Build the PE encryptor
echo "Building PE Encryptor..."

g++ -std=c++17 -O2 -Wall -Wextra \
    cross_platform_pe_encryptor.cpp \
    -o pe_encryptor \
    $(pkg-config --cflags --libs openssl) \
    -lpthread \
    2>&1 | tee build_pe.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "✓ PE Encryptor build successful!"
    chmod +x pe_encryptor
    
    echo ""
    echo "Usage:"
    echo "./pe_encryptor <input_file> <output_file>"
    echo ""
    echo "Example:"
    echo "./pe_encryptor malware.exe encrypted_malware.bin"
    echo ""
    echo "Features:"
    echo "- AES-256 encryption"
    echo "- PE header manipulation"
    echo "- Timestamp randomization"
    echo "- Rich header removal"
    echo "- Cross-platform compatibility"
else
    echo "✗ Build failed. Check build_pe.log for errors."
    exit 1
fi