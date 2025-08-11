#!/bin/bash

echo "🔥 UNLIMITED POLYMORPHIC OBFUSCATION GENERATOR 🔥"
echo "================================================="
echo ""

# Check for g++
if ! command -v g++ &> /dev/null; then
    echo "❌ Error: g++ not found! Please install build-essential"
    echo "   Ubuntu/Debian: sudo apt install build-essential"
    echo "   CentOS/RHEL: sudo yum groupinstall \"Development Tools\""
    exit 1
fi

echo "✅ Found g++ compiler"
echo ""

# Create output directory
mkdir -p generated_obfuscation
cd generated_obfuscation

echo "📁 Created output directory: generated_obfuscation/"
echo ""

echo "🚀 Phase 1: Building main polymorphic obfuscator..."
g++ -std=c++17 -O2 -Wall ../unlimited_polymorphic_obfuscator.cpp -o unlimited_obfuscator
if [ $? -eq 0 ]; then
    echo "✅ Built unlimited_obfuscator"
else
    echo "❌ Failed to build main obfuscator"
    exit 1
fi

echo ""
echo "🚀 Phase 2: Building advanced modules generator..."
g++ -std=c++17 -O2 -Wall ../advanced_polymorphic_modules.cpp -o advanced_modules
if [ $? -eq 0 ]; then
    echo "✅ Built advanced_modules"
else
    echo "❌ Failed to build advanced modules"
    exit 1
fi

echo ""
echo "🔥 Phase 3: Generating unlimited obfuscation variants..."
echo ""

echo "Generating basic polymorphic variants..."
./unlimited_obfuscator

echo ""
echo "Generating advanced polymorphic modules..."
./advanced_modules

echo ""
echo "🎯 Generation complete! Files created:"
echo "====================================="

# List all generated files
total_files=0
total_size=0

for file in *.cpp; do
    if [ -f "$file" ]; then
        size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
        echo "📄 $file ($(echo $size | awk '{printf "%.1f KB", $1/1024}'))"
        total_files=$((total_files + 1))
        total_size=$((total_size + size))
    fi
done

echo ""
echo "📊 SUMMARY:"
echo "Total files generated: $total_files"
echo "Total size: $(echo $total_size | awk '{printf "%.1f KB", $1/1024}')"
echo ""

echo "🔧 How to use the generated obfuscation:"
echo "========================================"
echo ""
echo "1. Each .cpp file contains unique obfuscation techniques"
echo "2. Compile any variant:"
echo "   g++ -std=c++17 -O2 polymorphic_variant_1.cpp -o obfuscated_program"
echo ""
echo "3. Use advanced modules in your projects:"
echo "   #include \"advanced_module_1.cpp\""
echo ""
echo "4. Every run generates completely different code!"
echo ""

echo "⚡ OBFUSCATION FEATURES AVAILABLE:"
echo "================================="
echo "• XOR Obfuscation (with random keys)"
echo "• ADD/SUB Arithmetic Obfuscation"
echo "• Bit Rotation Obfuscation"
echo "• Multi-stage Layered Obfuscation"
echo "• String Obfuscation"
echo "• Polymorphic Junk Code Injection"
echo "• Function Wrapping"
echo "• Random Variable/Function Naming"
echo "• Control Flow Obfuscation"
echo "• Data Structure Obfuscation"
echo "• Anti-Analysis Techniques"
echo "• Advanced Encoding Schemes"
echo "• Environment Detection"
echo "• Hardware Fingerprinting"
echo "• API Hook Detection"
echo ""

echo "🌟 ADVANCED TECHNIQUES:"
echo "======================"
echo "• Opaque Predicates"
echo "• Function Pointer Confusion"
echo "• Exception-based Control Flow"
echo "• State Machine Obfuscation"
echo "• Array Splitting"
echo "• Polynomial Encoding"
echo "• Matrix-based Encoding"
echo "• Fibonacci Sequence Encoding"
echo "• Custom Base64 Alphabets"
echo "• Huffman-like Encoding"
echo "• LZ77-like Compression"
echo "• Arithmetic Encoding"
echo ""

echo "💡 PRO TIPS:"
echo "============"
echo "• Run the generators multiple times for different variants"
echo "• Combine multiple obfuscation techniques"
echo "• Each generation uses different random seeds"
echo "• Modify the source generators for custom obfuscation"
echo "• Use -O3 optimization for maximum performance"
echo ""

echo "🔥 UNLIMITED POLYMORPHIC OBFUSCATION READY! 🔥"
echo ""

cd ..
echo "All files are in the 'generated_obfuscation/' directory"