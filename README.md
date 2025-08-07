# C++ AI Development Environment

A comprehensive C++ development environment designed for AI-assisted programming and learning.

## 🚀 Features

- **Modular Architecture**: Clean separation of concerns with header files and implementation
- **Multiple Tools**: Calculator, Number Guessing Game, String Utilities
- **Input Validation**: Robust error handling and user input validation
- **Professional Structure**: CMake build system, proper directory organization
- **AI-Friendly**: Well-documented code perfect for AI assistance

## 📁 Project Structure

```
├── CMakeLists.txt          # Main CMake configuration
├── build.sh               # Build script
├── README.md              # This file
├── include/               # Header files
│   ├── utils.h           # Utility functions and base classes
│   ├── calculator.h      # Calculator class interface
│   └── game.h           # Game class interface
├── src/                  # Source files
│   ├── main.cpp         # Main program entry point
│   ├── utils.cpp        # Utility function implementations
│   ├── calculator.cpp   # Calculator implementation
│   └── game.cpp        # Game implementation
├── tests/               # Test files (future)
├── examples/            # Example programs (future)
├── docs/               # Documentation (future)
└── build/              # Build output directory
```

## 🛠️ Building and Running

### Quick Start
```bash
./build.sh
cd build
./main
```

### Manual Build
```bash
mkdir build
cd build
cmake ..
make
./main
```

## 🎯 Available Tools

### 1. Calculator
- Basic operations (+, -, *, /)
- Advanced operations (power, square root)
- Memory functions
- Calculation history

### 2. Number Guessing Game
- Random number generation
- Attempt tracking
- Game statistics
- Input validation

### 3. String Utilities
- Case conversion (upper/lower)
- String reversal
- String trimming
- Length calculation

## 🧠 AI-Friendly Features

This environment is designed to work seamlessly with AI assistants:

- **Clear Function Names**: Descriptive, self-documenting code
- **Consistent Structure**: Predictable patterns throughout
- **Comprehensive Comments**: Well-documented functions and classes
- **Modular Design**: Easy to extend and modify
- **Error Handling**: Robust input validation and error messages

## 🔧 Development

### Adding New Tools
1. Create header file in `include/`
2. Create implementation in `src/`
3. Inherit from `BaseTool` class
4. Add to main menu in `src/main.cpp`

### Code Style
- Use meaningful variable names
- Add comments for complex logic
- Follow consistent indentation
- Include error handling

## 📚 Learning Resources

This project demonstrates:
- Object-oriented programming
- Inheritance and polymorphism
- File organization
- Build systems (CMake)
- Input/output operations
- Error handling
- Modular design

## 🤝 Contributing

Feel free to extend this environment with:
- New tools and utilities
- Additional games
- More advanced features
- Better documentation

## 📄 License

This project is open source and available for educational use. 
