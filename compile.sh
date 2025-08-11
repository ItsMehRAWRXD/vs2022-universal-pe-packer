#!/bin/bash

echo "Comprehensive Penetration Testing Framework - Build Script"
echo "========================================================="

# Detect operating system
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "Building for Windows..."
    # Windows build with MinGW
    g++ -std=c++17 -O2 -Wall -Wextra \
        -DWIN32_LEAN_AND_MEAN \
        comprehensive_pentest_framework.cpp \
        -o pentest_framework.exe \
        -lwininet -lws2_32 -lpthread \
        2>&1 | tee build.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "✓ Windows build successful!"
        echo "Run: ./pentest_framework.exe [target_url]"
    else
        echo "✗ Windows build failed. Check build.log for errors."
    fi
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Building for Linux..."
    
    # Check for required libraries
    echo "Checking dependencies..."
    
    # Check for libcurl
    if ! pkg-config --exists libcurl; then
        echo "Error: libcurl development package not found."
        echo "Install with: sudo apt-get install libcurl4-openssl-dev"
        echo "Or: sudo yum install libcurl-devel"
        exit 1
    fi
    
    # Linux build with libcurl
    g++ -std=c++17 -O2 -Wall -Wextra \
        comprehensive_pentest_framework.cpp \
        -o pentest_framework \
        $(pkg-config --cflags --libs libcurl) \
        -lpthread \
        2>&1 | tee build.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "✓ Linux build successful!"
        echo "Run: ./pentest_framework [target_url]"
        chmod +x pentest_framework
    else
        echo "✗ Linux build failed. Check build.log for errors."
    fi
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Building for macOS..."
    
    # Check for Homebrew curl
    if ! brew list curl &>/dev/null; then
        echo "Installing curl via Homebrew..."
        brew install curl
    fi
    
    # macOS build
    g++ -std=c++17 -O2 -Wall -Wextra \
        comprehensive_pentest_framework.cpp \
        -o pentest_framework \
        -lcurl -lpthread \
        -I/usr/local/include \
        -L/usr/local/lib \
        2>&1 | tee build.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "✓ macOS build successful!"
        echo "Run: ./pentest_framework [target_url]"
        chmod +x pentest_framework
    else
        echo "✗ macOS build failed. Check build.log for errors."
    fi
    
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo ""
echo "Framework Features:"
echo "- Blind SQL Injection with binary search"
echo "- Union-based SQL Injection with auto-detection"
echo "- Error-based SQL Injection"
echo "- Google Dork searching"
echo "- Web shell scanning and management"
echo "- Zombie network management (like checkip.php)"
echo "- Comprehensive wordlist integration"
echo "- Stealth HTTP client with random delays"
echo ""
echo "Usage Examples:"
echo "./pentest_framework                           # Interactive mode"
echo "./pentest_framework http://target.com/page.php?id=1  # Auto scan"
echo ""