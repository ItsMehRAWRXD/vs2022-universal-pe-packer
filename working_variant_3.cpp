#include <iostream>
#include <cstdint>

// ===== WORKING POLYMORPHIC OBFUSCATION =====
// Generation ID: 107119
// Timestamp: 1754531548

// Junk Code - Variant 8280
void junkFunction3233() {
    volatile int var4554 = 408;
    volatile int var6198 = 735;
    for (int i = 0; i < 100; ++i) {
        var4554 = (var4554 ^ var6198) + i;
        var6198 = (var6198 << 1) ^ var4554;
    }
    (void)var4554; (void)var6198; // Suppress warnings
}

// Rotation Obfuscation - Variant 7927
void func5255() {
    static uint8_t var1259[] = {
        0x42, 0x2b, 0x63, 0x63, 0x7b, 0x01, 0xba, 0x7b, 0x93, 0x63, 0x23, 0x09
    };

    // Decode using LEFT rotation
    for (size_t i = 0; i < sizeof(var1259); ++i) {
        var1259[i] = ((var1259[i] << 5) | (var1259[i] >> 3)) & 0xFF;
    }
    
    // Execute decoded data
    std::cout << "Decoded: ";
    for (size_t i = 0; i < sizeof(var1259); ++i) {
        std::cout << (char)var1259[i];
    }
    std::cout << std::endl;
}

// Junk Code - Variant 5333
void junkFunction7395() {
    volatile int var1608 = 946;
    volatile int var5549 = 243;
    for (int i = 0; i < 100; ++i) {
        var1608 = (var1608 ^ var5549) + i;
        var5549 = (var5549 << 1) ^ var1608;
    }
    (void)var1608; (void)var5549; // Suppress warnings
}

int main() {
    std::cout << "Polymorphic obfuscation demo" << std::endl;
    
    // Call obfuscated functions (you would call the generated function here)
    std::cout << "Obfuscation method 2 ready!" << std::endl;
    
    return 0;
}
