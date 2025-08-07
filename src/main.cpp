#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include "utils.h"
#include "calculator.h"
#include "game.h"
#include "assembler.h"

class AIEnvironment {
private:
    std::vector<std::unique_ptr<BaseTool>> tools;
    
public:
    AIEnvironment() {
        // Initialize tools
        tools.push_back(std::make_unique<Calculator>());
        tools.push_back(std::make_unique<Game>());
        tools.push_back(std::make_unique<MASMAssembler>());
    }
    
    void showMenu() {
        std::cout << "\n=== C++ AI Development Environment ===" << std::endl;
        std::cout << "1. Calculator" << std::endl;
        std::cout << "2. Number Guessing Game" << std::endl;
        std::cout << "3. String Utilities" << std::endl;
        std::cout << "4. Exit" << std::endl;
        std::cout << "Choose an option: ";
    }
    
    void run() {
        while (true) {
            showMenu();
            int choice;
            std::cin >> choice;
            
            switch (choice) {
                case 1:
                    tools[0]->run();
                    break;
                case 2:
                    tools[1]->run();
                    break;
                case 3:
                    runStringUtils();
                    break;
                case 4:
                    std::cout << "Goodbye!" << std::endl;
                    return;
                default:
                    std::cout << "Invalid option. Please try again." << std::endl;
            }
        }
    }
    
    void runStringUtils() {
        std::cout << "\n=== String Utilities ===" << std::endl;
        std::string input;
        std::cout << "Enter a string: ";
        std::cin.ignore();
        std::getline(std::cin, input);
        
        std::cout << "Original: " << input << std::endl;
        std::cout << "Uppercase: " << toUpperCase(input) << std::endl;
        std::cout << "Lowercase: " << toLowerCase(input) << std::endl;
        std::cout << "Reversed: " << reverseString(input) << std::endl;
        std::cout << "Length: " << input.length() << std::endl;
    }
};

int main() {
    std::cout << "🚀 Starting C++ AI Development Environment..." << std::endl;
    
    AIEnvironment env;
    env.run();
    
    return 0;
}