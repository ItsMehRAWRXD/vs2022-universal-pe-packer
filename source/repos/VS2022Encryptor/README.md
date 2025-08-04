# VS2022Encryptor

A simple PE (Portable Executable) packer/encryptor project.

## Building the Project

### Option 1: Using the build script (Linux/macOS)
```bash
./build.sh
```

### Option 2: Using CMake
```bash
mkdir build
cd build
cmake ..
make
```

### Option 3: Using Visual Studio 2022
1. Open `VS2022Encryptor.vcxproj` in Visual Studio 2022
2. Build the solution (Ctrl+Shift+B)
3. Run the application (F5)

### Option 4: Manual compilation with g++
```bash
g++ -std=c++17 -o VS2022Encryptor main.cpp
```

## Running the Application

After building, run the executable:
```bash
./VS2022Encryptor  # or ./build/VS2022Encryptor if using build script
```

## Troubleshooting

If you encounter blue screens or the application doesn't open:

1. **Missing dependencies**: Make sure you have the required build tools installed
2. **Corrupted project files**: The project file has been fixed to only include existing source files
3. **Permission issues**: Make sure the build script is executable (`chmod +x build.sh`)
4. **Compiler issues**: Try using a different compiler or build method

## Current Status

This is a basic template project. The main.cpp file currently just displays "PE Packer Ready!" and waits for user input. You can extend it to implement actual PE encryption functionality.