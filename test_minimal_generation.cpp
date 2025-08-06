#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Simulate what the packer generates
std::string generateMinimalTest() {
    std::string code = R"(#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cmath>
#include <random>
#include <shlobj.h>
#include <objbase.h>
#include <shlguid.h>

// Company: Adobe Systems Incorporated
// Certificate: Lenovo Certificate Authority
// Architecture: x64

// Test PE data (small sample)
unsigned char embedded_data[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
};

size_t embedded_data_size = 16;

void performBenignOperations() {
    // Realistic startup delay
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Check system legitimately (read-only)
    DWORD version = GetVersion();
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD nameSize = sizeof(computerName);
    GetComputerNameA(computerName, &nameSize);
    
    // Display benign message
    MessageBoxA(NULL, 
               "Test Company Application\n\nSystem check completed successfully.\n\nVersion: 1.0.0", 
               "Test Company", 
               MB_OK | MB_ICONINFORMATION);
}

int main() {
    performBenignOperations();
    return 0;
}
)";
    return code;
}

int main() {
    std::cout << "Generating minimal test file...\n";
    
    std::string code = generateMinimalTest();
    
    std::ofstream testFile("test_minimal.cpp");
    if (testFile.is_open()) {
        testFile << code;
        testFile.close();
        std::cout << "Generated: test_minimal.cpp\n";
        std::cout << "Code length: " << code.length() << " characters\n";
        
        std::cout << "\nTo test compilation manually, run:\n";
        std::cout << "cl.exe /nologo /O2 /EHsc /DNDEBUG /MD test_minimal.cpp /Fe:test_minimal.exe /link /MACHINE:X64 /SUBSYSTEM:CONSOLE user32.lib kernel32.lib\n";
    } else {
        std::cout << "Failed to create test file\n";
        return 1;
    }
    
    return 0;
}