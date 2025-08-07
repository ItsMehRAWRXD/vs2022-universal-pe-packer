#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "stealth_triple_encryptor.h"
#include "pe_encryptor.h"

using namespace std;

void printUsage() {
    cout << "PE Packer - Stealth Encryptor Tool\n";
    cout << "Usage:\n";
    cout << "  Pack:   encryptor.exe pack <input.exe> <output.exe> <key>\n";
    cout << "  Unpack: encryptor.exe unpack <input.exe> <output.exe> <key>\n";
    cout << "  Stealth Pack: encryptor.exe stealth <input.exe> <output.exe> <key>\n";
    cout << "\nFeatures:\n";
    cout << "  - Triple layer encryption\n";
    cout << "  - Anti-debug protection\n";
    cout << "  - Header obfuscation\n";
    cout << "  - PE structure validation\n";
}

int main(int argc, char* argv[]) {
    cout << "PE Packer Ready!" << endl;
    
    if (argc < 2) {
        printUsage();
        return 0;
    }
    
    string command = argv[1];
    
    if (command == "pack" && argc == 5) {
        string inputFile = argv[2];
        string outputFile = argv[3];
        string key = argv[4];
        
        PEEncryptor encryptor;
        cout << "Packing " << inputFile << " -> " << outputFile << endl;
        
        if (encryptor.packPE(inputFile, outputFile, key)) {
            cout << "Successfully packed PE file!" << endl;
        } else {
            cout << "Failed to pack PE file!" << endl;
            return 1;
        }
    }
    else if (command == "unpack" && argc == 5) {
        string inputFile = argv[2];
        string outputFile = argv[3];
        string key = argv[4];
        
        PEEncryptor encryptor;
        cout << "Unpacking " << inputFile << " -> " << outputFile << endl;
        
        if (encryptor.unpackPE(inputFile, outputFile, key)) {
            cout << "Successfully unpacked PE file!" << endl;
        } else {
            cout << "Failed to unpack PE file!" << endl;
            return 1;
        }
    }
    else if (command == "stealth" && argc == 5) {
        string inputFile = argv[2];
        string outputFile = argv[3];
        string key = argv[4];
        
        StealthTripleEncryptor encryptor;
        cout << "Stealth packing " << inputFile << " -> " << outputFile << endl;
        
        if (encryptor.packWithStealth(inputFile, outputFile, key)) {
            cout << "Successfully stealth packed PE file with anti-debug features!" << endl;
        } else {
            cout << "Failed to stealth pack PE file!" << endl;
            return 1;
        }
    }
    else if (command == "help" || command == "--help" || command == "-h") {
        printUsage();
    }
    else {
        cout << "Invalid command or arguments!" << endl;
        printUsage();
        return 1;
    }
    
    return 0;
} 
