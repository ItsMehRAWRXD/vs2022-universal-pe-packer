# C++ Quick Reference Card

## 🚀 Essential Commands

```bash
./build.sh          # Build project
cd build && ./main  # Run program
```

## 📝 Common Code Patterns

### Input/Output
```cpp
// Get number
int number = getValidInt("Enter number: ");

// Get text
std::string text;
std::cout << "Enter text: ";
std::cin.ignore();
std::getline(std::cin, text);

// Display
std::cout << "Result: " << result << std::endl;
```

### Menu System
```cpp
void showMenu() {
    clearScreen();
    printHeader("Tool Name");
    std::cout << "1. Option 1" << std::endl;
    std::cout << "2. Option 2" << std::endl;
    std::cout << "3. Exit" << std::endl;
}
```

### Switch Statement
```cpp
switch (choice) {
    case 1:
        // Do something
        break;
    case 2:
        // Do something else
        break;
    default:
        std::cout << "Invalid option!" << std::endl;
}
```

## 🔧 Data Types

| Type | Description | Example |
|------|-------------|---------|
| `int` | Integer | `int age = 25;` |
| `double` | Decimal | `double price = 19.99;` |
| `string` | Text | `string name = "John";` |
| `bool` | True/False | `bool isActive = true;` |
| `vector<T>` | Dynamic array | `vector<int> numbers;` |

## 📚 Common Functions

### String Operations
```cpp
toUpperCase(text)    // Convert to uppercase
toLowerCase(text)    // Convert to lowercase
reverseString(text)  // Reverse string
trim(text)          // Remove whitespace
```

### Display Functions
```cpp
clearScreen()        // Clear terminal
pauseScreen()        // Wait for Enter
printHeader(title)   // Print formatted header
printSeparator()     // Print separator line
```

### Validation Functions
```cpp
getValidInt(prompt)    // Get valid integer
getValidDouble(prompt) // Get valid decimal
isValidNumber(text)    // Check if text is number
```

## 🐛 Debugging Tips

### Common Errors
- **"File not found"** → Check file path
- **"Invalid input"** → Use validation functions
- **Build errors** → Check includes and declarations
- **Runtime crashes** → Add null checks

### Debug Output
```cpp
std::cout << "DEBUG: value = " << value << std::endl;
```

## 🔄 Adding New Tools

### 1. Create Header (`include/tool.h`)
```cpp
#pragma once
#include "utils.h"

class MyTool : public BaseTool {
public:
    void run() override;
};
```

### 2. Create Implementation (`src/tool.cpp`)
```cpp
#include "tool.h"

void MyTool::run() {
    // Your code here
}
```

### 3. Add to Main Menu (`src/main.cpp`)
```cpp
#include "tool.h"
tools.push_back(std::make_unique<MyTool>());
```

## 📖 File Operations

### Read File
```cpp
std::ifstream file("filename.txt");
if (file.is_open()) {
    std::string line;
    while (std::getline(file, line)) {
        // Process line
    }
    file.close();
}
```

### Write File
```cpp
std::ofstream file("output.txt");
if (file.is_open()) {
    file << "Your data" << std::endl;
    file.close();
}
```

## 🎯 Best Practices

1. **Always validate input**
2. **Handle errors gracefully**
3. **Use meaningful names**
4. **Keep functions small**
5. **Test thoroughly**

## 🆘 When Stuck

1. Check the **CODING_GUIDE.md** for detailed explanations
2. Look at **examples/** for working code
3. Use the **debugging tips** above
4. When online, ask AI for help!

## 📞 Emergency Commands

```bash
# Rebuild everything
rm -rf build && ./build.sh

# Check what's in a file
cat filename.cpp

# Find text in files
grep "searchterm" *.cpp

# List all files
ls -la
```