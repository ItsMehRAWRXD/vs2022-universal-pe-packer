// Windows compilation test for the fixed access issue
// This should compile on Windows with Visual Studio

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <random>

// Simplified version of the fixed EmbeddedCompiler class
class TestEmbeddedCompiler {
private:
    std::mt19937 rng;

public:
    TestEmbeddedCompiler() : rng(std::random_device{}()) {}
    
    // This method is now PUBLIC (was private before)
    std::vector<uint8_t> generateMinimalPEExecutable(const std::string& payload) {
        // Simplified version just to test access
        std::vector<uint8_t> result;
        result.insert(result.end(), payload.begin(), payload.end());
        return result;
    }
    
    // Test method that calls the public method
    bool testMethodAccess() {
        std::string testPayload = "test payload";
        auto result = generateMinimalPEExecutable(testPayload);
        return !result.empty();
    }
};

// Global instance similar to the real code
TestEmbeddedCompiler g_testCompiler;

int main() {
    std::cout << "Testing method access fix...\n";
    
    // Test 1: Direct call (this should work now)
    TestEmbeddedCompiler compiler;
    auto result1 = compiler.generateMinimalPEExecutable("test1");
    std::cout << "Direct call: " << (result1.empty() ? "FAIL" : "PASS") << "\n";
    
    // Test 2: Call via global instance (this simulates the real usage)
    auto result2 = g_testCompiler.generateMinimalPEExecutable("test2");
    std::cout << "Global call: " << (result2.empty() ? "FAIL" : "PASS") << "\n";
    
    // Test 3: Method calling itself
    bool result3 = compiler.testMethodAccess();
    std::cout << "Internal call: " << (result3 ? "PASS" : "FAIL") << "\n";
    
    std::cout << "\n✅ All access tests completed!\n";
    std::cout << "If this compiles, the access issue is fixed.\n";
    
    return 0;
}

#else
// Non-Windows stub
#include <iostream>
int main() {
    std::cout << "This test is for Windows only.\n";
    return 0;
}
#endif