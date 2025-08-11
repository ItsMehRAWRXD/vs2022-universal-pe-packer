#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

class RandomizedAPIResolver {
private:
    std::mt19937_64 rng;
    std::vector<std::string> usedVariableNames;
    
    // XOR string obfuscation
    struct XORString {
        std::vector<uint8_t> data;
        uint8_t key;
        
        XORString(const char* str) {
            // Generate random XOR key
            std::random_device rd;
            key = static_cast<uint8_t>(rd() % 256);
            
            size_t len = strlen(str);
            data.resize(len + 1);
            
            for (size_t i = 0; i < len; i++) {
                data[i] = static_cast<uint8_t>(str[i] ^ key);
            }
            data[len] = key; // Store key at end for runtime decryption
        }
        
        std::string decrypt() const {
            std::string result;
            result.resize(data.size() - 1);
            
            for (size_t i = 0; i < data.size() - 1; i++) {
                result[i] = static_cast<char>(data[i] ^ key);
            }
            return result;
        }
    };

public:
    RandomizedAPIResolver() : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()) {}
    
    // Generate random variable name for stealth
    std::string generateRandomVariableName(const std::string& prefix = "") {
        std::string varName;
        do {
            std::stringstream ss;
            if (!prefix.empty()) {
                ss << prefix << "_";
            }
            
            std::uniform_int_distribution<> lengthDist(8, 16);
            int length = lengthDist(rng);
            
            std::uniform_int_distribution<> charDist(0, 35);
            for (int i = 0; i < length; i++) {
                int val = charDist(rng);
                if (i == 0) {
                    // First character must be a letter
                    if (val < 26) {
                        ss << static_cast<char>('a' + val);
                    } else {
                        ss << static_cast<char>('A' + (val - 26) % 26);
                    }
                } else {
                    if (val < 26) {
                        ss << static_cast<char>('a' + val);
                    } else if (val < 52) {
                        ss << static_cast<char>('A' + (val - 26));
                    } else {
                        ss << static_cast<char>('0' + (val - 52) % 10);
                    }
                }
            }
            varName = ss.str();
        } while (std::find(usedVariableNames.begin(), usedVariableNames.end(), varName) != usedVariableNames.end());
        
        usedVariableNames.push_back(varName);
        return varName;
    }
    
    // Generate randomized dynamic API resolution code
    std::string generateRandomizedAPIResolution() {
        std::string code;
        
        // Generate random variable names
        std::string hModuleVar = generateRandomVariableName("hMod");
        std::string hKernel32Var = generateRandomVariableName("hK32");
        std::string procVar = generateRandomVariableName("proc");
        std::string resultVar = generateRandomVariableName("res");
        std::string ticksVar = generateRandomVariableName("tck");
        std::string sleepVar = generateRandomVariableName("slp");
        std::string checkVar = generateRandomVariableName("chk");
        
        // XOR obfuscated strings
        XORString kernel32Str("kernel32.dll");
        XORString getTickCountStr("GetTickCount");
        XORString sleepStr("Sleep");
        XORString loadLibraryStr("LoadLibraryA");
        XORString getProcAddrStr("GetProcAddress");
        XORString freeLibraryStr("FreeLibrary");
        
        code += "    // Randomized Dynamic API Resolution for stealth\n";
        code += "    {\n";
        
        // Generate consistent variable names for data arrays
        std::string k32DataVar = generateRandomVariableName("k32_data");
        std::string gtcDataVar = generateRandomVariableName("gtc_data");
        std::string slpDataVar = generateRandomVariableName("slp_data");
        std::string xorDecryptVar = generateRandomVariableName("xor_decrypt");
        
        // Generate XOR decryption inline functions
        code += "        auto " + xorDecryptVar + " = [](const unsigned char* data, size_t len) -> std::string {\n";
        code += "            std::string result;\n";
        code += "            if (len > 0) {\n";
        code += "                unsigned char key = data[len - 1];\n";
        code += "                result.resize(len - 1);\n";
        code += "                for (size_t i = 0; i < len - 1; i++) {\n";
        code += "                    result[i] = static_cast<char>(data[i] ^ key);\n";
        code += "                }\n";
        code += "            }\n";
        code += "            return result;\n";
        code += "        };\n\n";
        
        // Generate obfuscated string data
        code += "        const unsigned char " + k32DataVar + "[] = {";
        for (size_t i = 0; i < kernel32Str.data.size(); i++) {
            if (i > 0) code += ", ";
            code += "0x" + toHex(kernel32Str.data[i]);
        }
        code += "};\n";
        
        code += "        const unsigned char " + gtcDataVar + "[] = {";
        for (size_t i = 0; i < getTickCountStr.data.size(); i++) {
            if (i > 0) code += ", ";
            code += "0x" + toHex(getTickCountStr.data[i]);
        }
        code += "};\n";
        
        code += "        const unsigned char " + slpDataVar + "[] = {";
        for (size_t i = 0; i < sleepStr.data.size(); i++) {
            if (i > 0) code += ", ";
            code += "0x" + toHex(sleepStr.data[i]);
        }
        code += "};\n\n";
        
        // Add random delays and anti-debugging checks with dynamic API resolution
        std::uniform_int_distribution<> delayDist(1, 5);
        int randomDelay = delayDist(rng);
        std::string hKernelVar = generateRandomVariableName("hKernel");
        
        code += "        // Anti-debugging timing check using dynamic API resolution\n";
        code += "        HMODULE " + hKernelVar + " = LoadLibraryA(" + 
               xorDecryptVar + "(" + k32DataVar + ", sizeof(" + k32DataVar + ")).c_str());\n";
        code += "        if (" + hKernelVar + ") {\n";
        code += "            FARPROC " + ticksVar + "Proc = GetProcAddress(" + hKernelVar + ", " +
               xorDecryptVar + "(" + gtcDataVar + ", sizeof(" + gtcDataVar + ")).c_str());\n";
        code += "            FARPROC " + sleepVar + "Proc = GetProcAddress(" + hKernelVar + ", " +
               xorDecryptVar + "(" + slpDataVar + ", sizeof(" + slpDataVar + ")).c_str());\n";
        code += "            if (" + ticksVar + "Proc && " + sleepVar + "Proc) {\n";
        code += "                typedef DWORD(WINAPI* GetTickCountProc)();\n";
        code += "                typedef void(WINAPI* SleepProc)(DWORD);\n";
        code += "                GetTickCountProc " + ticksVar + "Fn = (GetTickCountProc)" + ticksVar + "Proc;\n";
        code += "                SleepProc " + sleepVar + "Fn = (SleepProc)" + sleepVar + "Proc;\n";
        code += "                DWORD " + ticksVar + "1 = " + ticksVar + "Fn();\n";
        code += "                " + sleepVar + "Fn(" + std::to_string(randomDelay) + ");\n";
        code += "                DWORD " + ticksVar + "2 = " + ticksVar + "Fn();\n";
        code += "                if ((" + ticksVar + "2 - " + ticksVar + "1) > " + std::to_string(randomDelay + 10) + ") {\n";
        code += "                    return; // Possible debugger detected\n";
        code += "                }\n";
        code += "            }\n";
        code += "            FreeLibrary(" + hKernelVar + ");\n";
        code += "        }\n\n";
        
        // Generate randomized module loading
        std::vector<std::string> modules = {"kernel32.dll", "ntdll.dll", "user32.dll"};
        std::shuffle(modules.begin(), modules.end(), rng);
        
        for (const auto& module : modules) {
            std::string moduleVar = generateRandomVariableName("hMod");
            std::string modDataVar = generateRandomVariableName("mod_data");
            XORString moduleStr(module.c_str());
            
            code += "        const unsigned char " + modDataVar + "[] = {";
            for (size_t i = 0; i < moduleStr.data.size(); i++) {
                if (i > 0) code += ", ";
                code += "0x" + toHex(moduleStr.data[i]);
            }
            code += "};\n";
            
            code += "        HMODULE " + moduleVar + " = LoadLibraryA(" + 
                   xorDecryptVar + "(" + modDataVar + ", sizeof(" + modDataVar + ")).c_str());\n";
            
            code += "        if (" + moduleVar + ") {\n";
            
            // Add random API function resolution
            std::vector<std::string> functions = {"GetTickCount", "Sleep", "GetCurrentProcessId", "GetCurrentThreadId"};
            std::shuffle(functions.begin(), functions.end(), rng);
            
            for (const auto& func : functions) {
                std::string funcVar = generateRandomVariableName("func");
                std::string funcDataVar = generateRandomVariableName("func_data");
                XORString funcStr(func.c_str());
                
                code += "            const unsigned char " + funcDataVar + "[] = {";
                for (size_t i = 0; i < funcStr.data.size(); i++) {
                    if (i > 0) code += ", ";
                    code += "0x" + toHex(funcStr.data[i]);
                }
                code += "};\n";
                
                code += "            FARPROC " + funcVar + " = GetProcAddress(" + moduleVar + ", " +
                       xorDecryptVar + "(" + funcDataVar + ", sizeof(" + funcDataVar + ")).c_str());\n";
                
                code += "            if (" + funcVar + ") {\n";
                if (func == "GetTickCount") {
                    code += "                typedef DWORD(WINAPI* GetTickCountProc)();\n";
                    code += "                GetTickCountProc " + procVar + " = (GetTickCountProc)" + funcVar + ";\n";
                    code += "                DWORD " + resultVar + " = " + procVar + "();\n";
                    code += "                (void)" + resultVar + "; // Use the result\n";
                } else if (func == "Sleep") {
                    code += "                typedef void(WINAPI* SleepProc)(DWORD);\n";
                    code += "                SleepProc " + sleepVar + " = (SleepProc)" + funcVar + ";\n";
                    code += "                " + sleepVar + "(" + std::to_string(delayDist(rng)) + ");\n";
                }
                code += "            }\n";
            }
            
            code += "            FreeLibrary(" + moduleVar + ");\n";
            code += "        }\n\n";
        }
        
        code += "    }\n";
        
        return code;
    }
    
    // Generate XOR obfuscated message box
    std::string generateObfuscatedMessageBox(const std::string& title, const std::string& message) {
        std::string code;
        
        XORString titleStr(title.c_str());
        XORString messageStr(message.c_str());
        
        std::string titleVar = generateRandomVariableName("title");
        std::string messageVar = generateRandomVariableName("msg");
        std::string decryptVar = generateRandomVariableName("decrypt");
        
        code += "    // XOR obfuscated message display\n";
        code += "    {\n";
        
        // XOR decryption function
        code += "        auto " + decryptVar + " = [](const unsigned char* data, size_t len) -> std::string {\n";
        code += "            std::string result;\n";
        code += "            if (len > 0) {\n";
        code += "                unsigned char key = data[len - 1];\n";
        code += "                result.resize(len - 1);\n";
        code += "                for (size_t i = 0; i < len - 1; i++) {\n";
        code += "                    result[i] = static_cast<char>(data[i] ^ key);\n";
        code += "                }\n";
        code += "            }\n";
        code += "            return result;\n";
        code += "        };\n\n";
        
        // Obfuscated title data
        code += "        const unsigned char " + titleVar + "_data[] = {";
        for (size_t i = 0; i < titleStr.data.size(); i++) {
            if (i > 0) code += ", ";
            code += "0x" + toHex(titleStr.data[i]);
        }
        code += "};\n";
        
        // Obfuscated message data
        code += "        const unsigned char " + messageVar + "_data[] = {";
        for (size_t i = 0; i < messageStr.data.size(); i++) {
            if (i > 0) code += ", ";
            code += "0x" + toHex(messageStr.data[i]);
        }
        code += "};\n\n";
        
        // Dynamic message box call
        code += "        std::string " + titleVar + " = " + decryptVar + "(" + titleVar + "_data, sizeof(" + titleVar + "_data));\n";
        code += "        std::string " + messageVar + " = " + decryptVar + "(" + messageVar + "_data, sizeof(" + messageVar + "_data));\n";
        code += "        \n";
        code += "        MessageBoxA(NULL, " + messageVar + ".c_str(), " + titleVar + ".c_str(), MB_OK | MB_ICONINFORMATION);\n";
        code += "    }\n";
        
        return code;
    }

private:
    std::string toHex(uint8_t value) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << static_cast<int>(value);
        std::string result = ss.str();
        if (result.length() == 1) result = "0" + result;
        return result;
    }
};