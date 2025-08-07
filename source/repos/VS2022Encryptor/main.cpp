#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "stealth_triple_encryptor.h"
#include "pe_encryptor.h"

using namespace std;

void printUsage() {
    cout << "=== PE PACKER SUITE - COLLABORATIVE CREATION ===" << endl;
    cout << "Authors: Human Collaborator + Claude Sonnet" << endl;
    cout << "Purpose: Educational cybersecurity research" << endl;
    cout << "Built: August 7, 2025" << endl;
    cout << "===============================================" << endl;
    cout << endl;
    cout << "Usage:" << endl;
    cout << "  pack <input.exe> <output.exe> <key>    - Basic PE packing" << endl;
    cout << "  unpack <input.exe> <output.exe> <key>  - Basic PE unpacking" << endl;
    cout << "  stealth <input.exe> <output.exe> <key> - Advanced stealth packing" << endl;
    cout << "  help                                   - Show this help" << endl;
    cout << endl;
    cout << "Example:" << endl;
    cout << "  ./encryptor pack original.exe packed.exe mykey123" << endl;
    cout << "  ./encryptor stealth original.exe stealth.exe secretkey" << endl;
    cout << endl;
    cout << "\"Built with curiosity, tested with courage!\"" << endl;
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
