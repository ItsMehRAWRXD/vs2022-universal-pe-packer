// Example: Simple File Manager Tool
// This demonstrates file operations and more complex functionality

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <iomanip>

class FileManager {
private:
    std::string currentDirectory;
    
    void listFiles() {
        std::cout << "\n=== Files in Current Directory ===" << std::endl;
        
        try {
            for (const auto& entry : std::filesystem::directory_iterator(currentDirectory)) {
                std::string filename = entry.path().filename().string();
                std::string type = entry.is_directory() ? "[DIR]" : "[FILE]";
                std::cout << type << " " << filename << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "Error reading directory: " << e.what() << std::endl;
        }
    }
    
    void readFile() {
        std::string filename;
        std::cout << "Enter filename to read: ";
        std::cin.ignore();
        std::getline(std::cin, filename);
        
        std::ifstream file(filename);
        if (file.is_open()) {
            std::cout << "\n=== File Contents ===" << std::endl;
            std::string line;
            int lineNumber = 1;
            while (std::getline(file, line)) {
                std::cout << std::setw(3) << lineNumber << ": " << line << std::endl;
                lineNumber++;
            }
            file.close();
        } else {
            std::cout << "Error: Could not open file!" << std::endl;
        }
    }
    
    void writeFile() {
        std::string filename;
        std::cout << "Enter filename to write: ";
        std::cin.ignore();
        std::getline(std::cin, filename);
        
        std::ofstream file(filename);
        if (file.is_open()) {
            std::cout << "Enter text (type 'END' on a new line to finish):" << std::endl;
            std::string line;
            while (std::getline(std::cin, line) && line != "END") {
                file << line << std::endl;
            }
            file.close();
            std::cout << "File written successfully!" << std::endl;
        } else {
            std::cout << "Error: Could not create file!" << std::endl;
        }
    }
    
    void fileInfo() {
        std::string filename;
        std::cout << "Enter filename: ";
        std::cin.ignore();
        std::getline(std::cin, filename);
        
        try {
            std::filesystem::path filePath(filename);
            if (std::filesystem::exists(filePath)) {
                std::cout << "\n=== File Information ===" << std::endl;
                std::cout << "Name: " << filePath.filename() << std::endl;
                std::cout << "Size: " << std::filesystem::file_size(filePath) << " bytes" << std::endl;
                std::cout << "Type: " << (std::filesystem::is_directory(filePath) ? "Directory" : "File") << std::endl;
            } else {
                std::cout << "File does not exist!" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << std::endl;
        }
    }
    
public:
    FileManager() {
        currentDirectory = std::filesystem::current_path().string();
    }
    
    void run() {
        while (true) {
            std::cout << "\n=== File Manager ===" << std::endl;
            std::cout << "Current directory: " << currentDirectory << std::endl;
            std::cout << "1. List files" << std::endl;
            std::cout << "2. Read file" << std::endl;
            std::cout << "3. Write file" << std::endl;
            std::cout << "4. File information" << std::endl;
            std::cout << "5. Back to Main Menu" << std::endl;
            
            int choice;
            std::cout << "Choose an option: ";
            std::cin >> choice;
            
            switch (choice) {
                case 1:
                    listFiles();
                    break;
                case 2:
                    readFile();
                    break;
                case 3:
                    writeFile();
                    break;
                case 4:
                    fileInfo();
                    break;
                case 5:
                    return;
                default:
                    std::cout << "Invalid option!" << std::endl;
            }
        }
    }
};

// Example usage:
// int main() {
//     FileManager manager;
//     manager.run();
//     return 0;
// }