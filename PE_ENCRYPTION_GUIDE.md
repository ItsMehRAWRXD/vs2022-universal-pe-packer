# Simple PE Encryption Tool

A working PE file encryption tool that actually encrypts real executables.

## 🚀 Quick Start

### Windows:
```batch
# Run the complete test
test_pe_encryption.bat

# Or build manually
build_pe_encryptor.bat
```

### Linux:
```bash
# Build the tool
chmod +x build_pe_encryptor.sh
./build_pe_encryptor.sh
```

## 📋 Requirements

**Windows:**
- MinGW-w64 or MSYS2 with g++
- Download from: https://www.msys2.org/

**Linux:**
- GCC/G++ compiler
- `sudo apt install build-essential` (Ubuntu/Debian)

## 🔧 Usage

```bash
# Basic usage
pe_encryptor.exe input.exe output.exe

# Examples
pe_encryptor.exe notepad.exe encrypted_notepad.exe
pe_encryptor.exe calc.exe encrypted_calc.exe
pe_encryptor.exe myprogram.exe encrypted_myprogram.exe
```

## 🛠️ How It Works

1. **Read Input File**: Loads any PE executable into memory
2. **Generate Key**: Creates a random 32-byte XOR key
3. **Encrypt**: XOR encrypts the entire file
4. **Generate Loader**: Creates C++ source code with embedded encrypted data
5. **Compile**: Automatically compiles the loader into a new PE file
6. **Execute**: The new PE decrypts and runs the original program

## 📁 Files Created

- `pe_encryptor.exe` - The encryption tool
- `encrypted_program.exe` - Your encrypted executable
- Temporary `.cpp` files are automatically cleaned up

## ✅ Features

- ✅ **Actually works** with real PE files
- ✅ **Simple XOR encryption** (fast and effective)
- ✅ **Automatic compilation** (no manual steps)
- ✅ **Cross-platform** (Windows/Linux)
- ✅ **No dependencies** (static linking)
- ✅ **Clean output** (removes temporary files)

## 🔍 Technical Details

**Encryption Method:** XOR with 32-byte random key
**Loader Method:** Embedded C++ source generation
**Compilation:** G++ with static linking
**Execution:** Temp file creation and process spawning

## 🚨 Troubleshooting

**"g++ not found":**
- Install MinGW-w64 or MSYS2
- Add to PATH environment variable

**"Compilation failed":**
- Check file permissions
- Ensure enough disk space
- Try running as administrator

**"Cannot open input file":**
- Check file path is correct
- Ensure file exists and is readable
- Try absolute path instead of relative

## 💡 Tips

- Test with small programs first (like calc.exe)
- Keep backups of original files
- The encrypted file is portable (no external dependencies)
- Works with any PE file (exe, dll, etc.)

## 🎯 Real-World Usage

```batch
# Encrypt system utilities
pe_encryptor.exe C:\Windows\System32\calc.exe my_calc.exe
pe_encryptor.exe C:\Windows\System32\notepad.exe my_notepad.exe

# Encrypt your own programs  
pe_encryptor.exe myapp.exe protected_myapp.exe
pe_encryptor.exe game.exe encrypted_game.exe
```

The encrypted programs run exactly like the originals but are protected by encryption!