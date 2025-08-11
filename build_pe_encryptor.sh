#!/bin/bash
echo "Building Simple PE Encryptor..."

# Check if g++ is available
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ not found! Please install build-essential"
    echo "Ubuntu/Debian: sudo apt install build-essential"
    echo "CentOS/RHEL: sudo yum groupinstall \"Development Tools\""
    exit 1
fi

echo "[+] Compiling PE Encryptor..."
g++ -std=c++11 -O2 -static -s simple_pe_encryptor.cpp -o pe_encryptor

if [ $? -eq 0 ]; then
    echo "[+] Build successful! Created pe_encryptor"
    echo ""
    echo "Usage Examples:"
    echo "  ./pe_encryptor /bin/ls encrypted_ls"
    echo "  ./pe_encryptor myprogram encrypted_myprogram"
    echo ""
    chmod +x pe_encryptor
else
    echo "[-] Build failed!"
    exit 1
fi