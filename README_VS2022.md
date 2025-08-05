# VS2022 Universal PE Packer - Visual Studio 2022 Edition

## Overview

The VS2022 Universal PE Packer is a clean, Windows-optimized version designed specifically for Visual Studio 2022 compilation. This version removes all Unicode characters and uses standard ASCII, ensuring perfect compatibility with Visual Studio 2022.

## Features

### Encryption Algorithms
- **ChaCha20 (256-bit)** - RFC 7539 compliant stream cipher
- **AES Stream Cipher** - Custom implementation with S-box transformations
- **Enhanced XOR** - Variable-length keys with position-dependent mixing
- **Triple-Layer** - Randomized application order (6 combinations)
- **Decimal Key Obfuscation** - Large integer string encoding

### Windows-Specific Features
- **Enhanced WinINet Integration** - Automatic timeout handling, better error reporting
- **Windows CryptoAPI Integration** - Cryptographically secure random generation
- **High-Resolution Performance Counters** - Enhanced entropy collection
- **Windows-Specific Error Handling** - Detailed error codes and messages
- **Enhanced Drag & Drop Support** - Multi-file command line processing

## Quick Start

### Prerequisites
- **Visual Studio 2022** (Community, Professional, or Enterprise)
- **Windows 10/11** (Windows 7/8.1 also supported)
- **Windows SDK** (included with Visual Studio 2022)

### Compilation

#### Option 1: Using the Batch File (Recommended)
```batch
# Simply double-click compile_vs2022.bat
# Or run from Developer Command Prompt:
compile_vs2022.bat
```

#### Option 2: Manual Compilation
```batch
# From Developer Command Prompt:
cl /std:c++17 /O2 /DWIN32_LEAN_AND_MEAN /MT VS2022_MenuEncryptor_Clean.cpp /Fe:VS2022_Packer.exe wininet.lib advapi32.lib shell32.lib
```

#### Option 3: Visual Studio IDE
1. Open Visual Studio 2022
2. Create new C++ Console Application
3. Replace the default code with `VS2022_MenuEncryptor_Clean.cpp`
4. Add libraries: `wininet.lib`, `advapi32.lib`, `shell32.lib`
5. Set C++ Language Standard to C++17
6. Build the project

## Usage

### Interactive Mode
```batch
VS2022_Packer.exe
```

### Drag & Drop Mode
Simply drag files onto `VS2022_Packer.exe`

### Command Line Mode
```batch
VS2022_Packer.exe file1.exe file2.dll file3.bin
```

## Operation Modes

| Mode | Description | Status |
|------|-------------|---------|
| 1 | Pack File (AES) | Framework Ready |
| 2 | Pack File (ChaCha20) | Framework Ready |
| 3 | Pack File (Triple) | Framework Ready |
| 4 | Basic File Encryption | **FULLY IMPLEMENTED** |
| 5 | Generate MASM Stub | Framework Ready |
| 6 | URL Crypto Service (AES) | Framework Ready |
| 7 | URL Crypto Service (Triple) | Framework Ready |
| 8 | URL Crypto Service (ChaCha20) | Framework Ready |
| 9 | URL Crypto Service (Basic) | Framework Ready |
| 10 | URL Pack File (AES) | Framework Ready |
| 11 | URL Pack File (ChaCha20) | Framework Ready |
| 12 | URL Pack File (Triple) | Framework Ready |
| 13 | Local Crypto Service (AES) | Framework Ready |
| 14 | Local Crypto Service (ChaCha20) | Framework Ready |
| 15 | Local Crypto Service (Triple) | Framework Ready |

## Technical Details

### Compiler Flags
- `/std:c++17` - C++17 language standard
- `/O2` - Optimize for speed
- `/DWIN32_LEAN_AND_MEAN` - Exclude rarely-used Windows headers
- `/MT` - Multi-threaded static library (no runtime dependencies)

### Required Libraries
- `wininet.lib` - HTTP/HTTPS functionality
- `advapi32.lib` - Windows CryptoAPI
- `shell32.lib` - Shell functions

### Windows API Integration
```cpp
// Enhanced WinINet with timeout handling
DWORD timeout = 30000; // 30 seconds
InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));

// Windows CryptoAPI for secure random
HCRYPTPROV hProv;
CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
CryptGenRandom(hProv, sizeof(random_val), (BYTE*)&random_val);

// High-resolution performance counter
LARGE_INTEGER perf_counter;
QueryPerformanceCounter(&perf_counter);
```

## Troubleshooting

### Common Issues

#### "cl.exe not found"
```batch
# Solution: Use Developer Command Prompt
# Or run vcvars64.bat:
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

#### "Cannot open include file"
```batch
# Solution: Ensure Windows SDK is installed
# In Visual Studio Installer, modify and add:
# - Windows 10/11 SDK
# - MSVC v143 toolset
```

#### "Unresolved external symbol"
```batch
# Solution: Add required libraries
cl /std:c++17 /O2 VS2022_MenuEncryptor_Clean.cpp /Fe:VS2022_Packer.exe wininet.lib advapi32.lib shell32.lib
```

#### "Permission denied"
```batch
# Solution: Run as Administrator
# Or check file permissions
```

### Debug Mode
```batch
# Compile with debug information
cl /std:c++17 /Zi /Od /DWIN32_LEAN_AND_MEAN VS2022_MenuEncryptor_Clean.cpp /Fe:VS2022_Packer_debug.exe wininet.lib advapi32.lib
```

## Examples

### Basic File Encryption
```batch
VS2022_Packer.exe
# Choose option 4: Basic File Encryption
# Enter input file: C:\path\to\file.exe
# Enter output file: C:\path\to\encrypted.bin
```

### Drag & Drop Processing
```batch
# Drag multiple files onto VS2022_Packer.exe
# Each file will be processed with the selected encryption method
```

## Security Features

### Anti-Analysis Protection
- **Polymorphic Variables** - Unique naming per generation
- **Randomized Function Names** - Dynamic identifier generation
- **Junk Data Injection** - Polymorphic noise in assembly
- **Decimal Key Encoding** - Large integer obfuscation
- **Randomized Encryption Order** - 6 different algorithm sequences

### Cryptographic Security
- **256-bit ChaCha20** - RFC 7539 compliant
- **Custom AES Stream** - Enhanced with S-box transformations
- **Enhanced XOR** - Position-dependent mixing
- **Triple-layer Protection** - Multiple encryption layers
- **Secure Entropy** - Windows CryptoAPI integration

## Performance

### Optimization Features
- **Stream-based Processing** - Memory efficient for large files
- **Block Processing** - 64-byte ChaCha20 blocks
- **Minimal Dependencies** - Self-contained executables
- **Automatic Cleanup** - Temporary file management
- **Progress Indicators** - Real-time operation feedback

### File Size Limits
- **Recommended**: Up to 100MB
- **Supported**: Up to 2GB (limited by available memory)
- **Large Files**: Use Basic encryption mode for files >50MB

## Version Information

### Current Version: v2.0 Clean
- ✅ Clean ASCII-only code
- ✅ Visual Studio 2022 compatibility
- ✅ Enhanced Windows integration
- ✅ Basic file encryption implemented
- ✅ Framework for all 15 operation modes
- ✅ Drag & drop support
- ✅ Windows CryptoAPI integration

### Previous Versions
- **v1.9**: Added URL services and ChaCha20
- **v1.8**: Initial release with basic functionality

## System Requirements

- **OS**: Windows 7/8.1/10/11 (x64 recommended)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 100MB free space
- **Network**: Internet connection for URL features
- **Compiler**: Visual Studio 2022 (any edition)

## Support

### GitHub Repository
https://github.com/ItsMehRAWRXD/vs2022-universal-pe-packer

### Issues and Bug Reports
Report bugs and feature requests via GitHub Issues

### Community
- **Discord**: Join our development community
- **Telegram**: Get instant updates and support
- **Email**: Direct support for enterprise users

## License

This software is provided for educational and research purposes. Users are responsible for compliance with applicable laws and regulations.

---

**Ready to use the VS2022 Universal PE Packer with Visual Studio 2022!**