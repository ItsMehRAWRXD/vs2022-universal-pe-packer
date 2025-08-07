# BenignPacker Build Instructions

## Overview
This project contains a comprehensive penetration testing framework with plugin architecture for stub generation, encryption, and exploit capabilities.

## Prerequisites
- Visual Studio 2022 (Community, Professional, or Enterprise)
- C++ build tools for Visual Studio 2022
- Windows 10/11 SDK
- MSVC v143 compiler

## Project Structure
```
BenignPacker/
├── BenignPacker.sln                    # Main Visual Studio solution
├── BenignPacker/                       # Main application project
│   └── BenignPacker.vcxproj
├── PluginFramework/                    # Plugin framework library
│   ├── IPlugin.h
│   └── PluginFramework.vcxproj
├── Plugins/                           # Plugin projects
│   ├── UniqueStub71Plugin/
│   │   └── UniqueStub71Plugin.vcxproj
│   └── MASMAssemblerPlugin/
│       └── MASMAssemblerPlugin.vcxproj
├── BenignPacker.cpp                   # Main application source
├── UniqueStub71Plugin.h               # Plugin header
├── UniqueStub71Plugin.cpp             # Plugin implementation
├── MASMAssemblerPlugin.cpp            # MASM plugin implementation
└── build_visual_studio.bat            # Build script
```

## Building the Project

### Method 1: Using the Build Script (Recommended)
1. Open Command Prompt as Administrator
2. Navigate to the project directory
3. Run the build script:
   ```cmd
   build_visual_studio.bat
   ```

### Method 2: Using Visual Studio IDE
1. Open Visual Studio 2022
2. Open the solution file: `BenignPacker.sln`
3. Set configuration to `Release` and platform to `x64`
4. Build the solution (Ctrl+Shift+B)

### Method 3: Using MSBuild Command Line
1. Open "Developer Command Prompt for VS 2022"
2. Navigate to the project directory
3. Run:
   ```cmd
   msbuild BenignPacker.sln /p:Configuration=Release /p:Platform=x64 /m
   ```

## Output
After successful build, the executable will be located at:
```
BenignPacker\Release\x64\BenignPacker.exe
```

## Usage
```cmd
BenignPacker.exe <input_file> [output_file] [method]
```

### Examples
```cmd
# Basic usage
BenignPacker.exe payload.bin

# Specify output file
BenignPacker.exe payload.bin output.exe

# Use specific method
BenignPacker.exe payload.bin output.exe advanced

# Available methods: default, advanced, mutex, stealth
```

## Supported Input Formats
- `.bin` - Binary files
- `.exe` - Executable files
- `.dll` - Dynamic libraries
- `.raw` - Raw binary data
- `.shellcode` - Shellcode files

## Features
- **Plugin Architecture**: Modular design with plugin support
- **Multiple Stub Types**: Basic, advanced, mutex-protected, stealth
- **Anti-Analysis**: Debugger detection, VM detection, sandbox evasion
- **Encryption**: AES, XOR, RC4, ChaCha20 support
- **Company Spoofing**: Microsoft, Adobe, Google, NVIDIA, Intel profiles
- **Mutex Systems**: 40+ advanced mutex protection methods
- **Exploit Methods**: UAC bypass, privilege escalation, process injection

## Troubleshooting

### Common Build Errors

1. **"Cannot find cl.exe"**
   - Solution: Run from Visual Studio Developer Command Prompt
   - Or install C++ build tools for Visual Studio 2022

2. **"Cannot open include file 'windows.h'"**
   - Solution: Install Windows SDK via Visual Studio Installer

3. **"Cannot open include file 'IPlugin.h'"**
   - Solution: Verify PluginFramework directory exists and contains IPlugin.h

4. **"Namespace conflicts"**
   - Solution: All namespace conflicts have been resolved in the current version

5. **"String stream errors"**
   - Solution: All string stream issues have been fixed with proper includes

### Plugin Loading Issues
- Ensure all plugin DLLs are compiled for the same architecture (x64/x86)
- Check that plugin export functions are properly defined
- Verify plugin dependencies are satisfied

## Development Notes
- The project uses C++17 standard
- All plugins implement the `IStubGenerator` interface
- The framework supports both static and dynamic plugin loading
- Anti-analysis features are configurable per plugin
- Polymorphic code generation is available for obfuscation

## Security Notice
This framework is designed for educational and authorized penetration testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support
For build issues:
1. Check that Visual Studio 2022 is properly installed
2. Verify all prerequisites are met
3. Ensure all source files are present in the correct locations
4. Check the build log for specific error messages

## Version Information
- Framework Version: 1.0.0
- Plugin API Version: 1
- Compatible with: Visual Studio 2022
- Target Platform: Windows 10/11 x64