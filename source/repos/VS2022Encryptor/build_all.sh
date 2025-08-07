#!/bin/bash

echo "===================================="
echo "PE Packer Suite - Build from Source"
echo "===================================="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[1/4]${NC} Compiling generators..."
g++ -std=c++17 -O2 -o test_pe_generator test_pe_generator.cpp
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to compile test_pe_generator${NC}"
    exit 1
fi

g++ -std=c++17 -O2 -o stub_generator stub_generator.cpp
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to compile stub_generator${NC}"
    exit 1
fi

g++ -std=c++17 -O2 -o mass_stub_generator mass_stub_generator.cpp
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to compile mass_stub_generator${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Generators compiled successfully"

echo
echo -e "${BLUE}[2/4]${NC} Compiling main tools..."
g++ -std=c++17 -O2 -o encryptor main.cpp pe_encryptor.cpp stealth_triple_encryptor.cpp
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to compile encryptor${NC}"
    exit 1
fi

g++ -std=c++17 -O2 -o comprehensive_tester comprehensive_tester.cpp
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to compile comprehensive_tester${NC}"
    exit 1
fi

g++ -std=c++17 -O2 -o sample_test sample_test.cpp
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to compile sample_test${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Main tools compiled successfully"

echo
echo -e "${BLUE}[3/4]${NC} Generating PE test files..."
./test_pe_generator
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to generate PE test files${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} 10 PE test files generated"

echo
echo -e "${BLUE}[4/4]${NC} Generating stub variants..."
echo "  Generating 25 basic stubs..."
./stub_generator
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to generate basic stubs${NC}"
    exit 1
fi

echo "  Generating 100 advanced stubs..."
./mass_stub_generator
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to generate advanced stubs${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} 125 stub variants generated"

echo
echo "===================================="
echo -e "${GREEN}BUILD COMPLETE!${NC}"
echo "===================================="
echo
echo "Generated files:"
echo "  • 6 Tools (encryptor, generators, testers)"
echo "  • 10 Test PE files (basic + complex)"
echo "  • 125 Stub variants (25 basic + 100 advanced)"
echo "  • Total: 141 executable files"
echo
echo "Next steps:"
echo "  1. Run './encryptor help' for usage"
echo "  2. Test with './sample_test'"
echo "  3. Read README_USAGE.md for details"
echo
echo "File count verification:"
EXECUTABLE_COUNT=$(ls -1 *.exe 2>/dev/null | wc -l)
if [ $EXECUTABLE_COUNT -gt 0 ]; then
    echo "  Found $EXECUTABLE_COUNT executable files"
else
    EXECUTABLE_COUNT=$(ls -1 encryptor test_pe_generator stub_generator mass_stub_generator comprehensive_tester sample_test 2>/dev/null | wc -l)
    echo "  Found $EXECUTABLE_COUNT tool executables"
fi
echo