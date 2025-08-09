# C++ Coding Guide - Offline Reference

## 🚀 Quick Start

### Building Your Project
```bash
./build.sh          # Build everything
cd build && ./main  # Run the program
```

### Adding New Features
1. Create header file in `include/`
2. Create implementation in `src/`
3. Add to main menu in `src/main.cpp`
4. Build and test

## 📝 Code Templates

### Template 1: New Tool Class
```cpp
// include/newtool.h
#pragma once
#include "utils.h"

class NewTool : public BaseTool {
private:
    // Add your private members here
    
public:
    NewTool() {} // Constructor
    void run() override; // Main function
};
```

```cpp
// src/newtool.cpp
#include "newtool.h"

void NewTool::run() {
    while (true) {
        clearScreen();
        printHeader("New Tool");
        
        std::cout << "1. Feature 1" << std::endl;
        std::cout << "2. Feature 2" << std::endl;
        std::cout << "3. Back to Main Menu" << std::endl;
        
        int choice = getValidInt("Choose an option: ");
        
        switch (choice) {
            case 1:
                // Your feature 1 code
                break;
            case 2:
                // Your feature 2 code
                break;
            case 3:
                return;
            default:
                std::cout << "Invalid option!" << std::endl;
        }
        pauseScreen();
    }
}
```

### Template 2: Input Validation
```cpp
// Get a number from user
int number = getValidInt("Enter a number: ");

// Get text from user
std::string text;
std::cout << "Enter text: ";
std::cin.ignore();
std::getline(std::cin, text);

// Validate number range
if (number < 1 || number > 100) {
    std::cout << "Number must be between 1 and 100!" << std::endl;
    return;
}
```

### Template 3: File Operations
```cpp
#include <fstream>

// Read from file
std::ifstream file("filename.txt");
if (file.is_open()) {
    std::string line;
    while (std::getline(file, line)) {
        // Process each line
        std::cout << line << std::endl;
    }
    file.close();
}

// Write to file
std::ofstream outFile("output.txt");
if (outFile.is_open()) {
    outFile << "Your data here" << std::endl;
    outFile.close();
}
```

## 🔧 Common Patterns

### Menu System
```cpp
void showMenu() {
    clearScreen();
    printHeader("Your Tool Name");
    
    std::cout << "1. Option 1" << std::endl;
    std::cout << "2. Option 2" << std::endl;
    std::cout << "3. Exit" << std::endl;
}
```

### Error Handling
```cpp
try {
    // Your code here
    if (error_condition) {
        throw std::runtime_error("Error message");
    }
} catch (const std::exception& e) {
    std::cout << "Error: " << e.what() << std::endl;
    pauseScreen();
}
```

### Data Structures
```cpp
// Vector (dynamic array)
std::vector<int> numbers;
numbers.push_back(42);
numbers.push_back(100);

// Map (key-value pairs)
std::map<std::string, int> scores;
scores["Alice"] = 100;
scores["Bob"] = 85;

// Set (unique values)
std::set<int> uniqueNumbers;
uniqueNumbers.insert(1);
uniqueNumbers.insert(2);
```

## 🐛 Debugging Guide

### Common Issues and Solutions

#### 1. "File not found" error
- Check file path is correct
- Ensure file exists
- Use absolute paths if needed

#### 2. "Invalid input" errors
- Always use `getValidInt()` or `getValidDouble()`
- Clear input buffer with `std::cin.ignore()`
- Check input ranges

#### 3. Build errors
- Check all header files are included
- Ensure method declarations match implementations
- Verify CMakeLists.txt is correct

#### 4. Runtime crashes
- Check for null pointers
- Validate array indices
- Use try-catch blocks

### Debugging Tips
```cpp
// Add debug output
std::cout << "DEBUG: Variable = " << variable << std::endl;

// Check if file opened
if (!file.is_open()) {
    std::cout << "ERROR: Could not open file!" << std::endl;
    return;
}

// Validate data
if (data.empty()) {
    std::cout << "WARNING: No data to process" << std::endl;
    return;
}
```

## 📚 C++ Concepts Explained

### Classes and Objects
```cpp
class MyClass {
private:
    int privateData;  // Only accessible within class
    
public:
    int publicData;   // Accessible from anywhere
    
    void setData(int value) {
        privateData = value;  // Can access private members
    }
    
    int getData() {
        return privateData;
    }
};
```

### Inheritance
```cpp
class Animal {
public:
    virtual void makeSound() = 0;  // Pure virtual function
};

class Dog : public Animal {
public:
    void makeSound() override {
        std::cout << "Woof!" << std::endl;
    }
};
```

### Pointers and References
```cpp
int number = 42;
int* pointer = &number;    // Pointer to number
int& reference = number;   // Reference to number

*pointer = 100;            // Change value through pointer
reference = 200;           // Change value through reference
```

## 🎯 Best Practices

1. **Always validate input** - Use the provided validation functions
2. **Handle errors gracefully** - Don't let programs crash
3. **Use meaningful names** - Make code self-documenting
4. **Keep functions small** - One function, one purpose
5. **Comment complex logic** - Explain what, not how
6. **Test thoroughly** - Try edge cases and invalid input

## 🔄 Adding to Main Menu

To add your new tool to the main menu:

1. **Include your header** in `src/main.cpp`:
```cpp
#include "yourtool.h"
```

2. **Add to tools vector**:
```cpp
tools.push_back(std::make_unique<YourTool>());
```

3. **Add menu option**:
```cpp
case 3:
    tools[2]->run();  // Adjust index as needed
    break;
```

## 📖 Next Steps

1. **Start simple** - Add basic features first
2. **Build incrementally** - Test each addition
3. **Use existing patterns** - Follow the established structure
4. **Ask for help** - When online, get AI assistance
5. **Document your changes** - Keep notes of what you add

Remember: This environment is designed to grow with you. Start with simple additions and gradually build more complex features!