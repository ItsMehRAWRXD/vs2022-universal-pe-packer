# VS2022 Menu Encryptor

A sophisticated C++ encryption tool with a Visual Studio 2022-themed interface featuring triple-layer encryption.

## Features

- **Triple-Layer Encryption**: Combines ChaCha20, AES-256, and XOR encryption
- **Cross-Platform**: Works on Windows and Linux
- **Self-Compilation**: Can compile itself automatically
- **Interactive Menu**: Visual Studio 2022-styled interface
- **Command Line Interface**: Full CLI support for automation
- **File Encryption**: Encrypt/decrypt entire files
- **Secure Random Generation**: Uses OS-provided cryptographic randomness

## Compilation

```bash
g++ -std=c++17 -O2 vs2022_menu_encryptor.cpp -o vs2022_menu_encryptor
```

## Usage

### Interactive Mode
```bash
./vs2022_menu_encryptor
```

### Command Line Mode
```bash
# Encrypt data
./vs2022_menu_encryptor --encrypt "Hello World!"

# Decrypt data
./vs2022_menu_encryptor --decrypt "encrypted_string_here"

# Encrypt/decrypt files
./vs2022_menu_encryptor --file myfile.txt

# Self-compile
./vs2022_menu_encryptor --compile vs2022_menu_encryptor.cpp

# Show help
./vs2022_menu_encryptor --help
```

## Security Features

- ChaCha20 stream cipher for fast, secure encryption
- AES-256 in XOR mode for additional security layer
- Custom XOR encryption with unique keys
- Cryptographically secure random key generation
- Keys are embedded with encrypted data for portability

## Menu Options

1. 🔐 Encrypt Sensitive Data
2. 🔓 Decrypt Protected Data  
3. 🔑 Generate Security Keys
4. 📁 Process File Batch
5. 🛡️ Security Analysis
6. ⚙️ Advanced Settings
7. 📊 System Information
8. 🌐 Network Operations
9. 💾 Backup Operations
10. 🔄 Update Components
11. 🎯 Target Selection
12. 🚀 Deploy Payload
13. 📈 Performance Monitor
14. 🔍 Search & Filter
15. ❌ Exit Application

*Note: Options 5-14 are currently in development and show placeholder functionality.*

## Example

```bash
$ ./vs2022_menu_encryptor --encrypt "Secret Message"
3e7988abb35c709f6f3e26e9666750f98bdbc21bcfe53ce9f53104648d890c70:a88eb89acfe2f145df49de1d2242eb44f8bc01a1c369413b80e0d703ef8151da:0d39fb97b4d8ee02cd925d5196c3084f12be39bb57fc23cee3edc0856c57aafa:b99b8a1497b5dc22a44f6f0f:58d737d12869fbc4936d36df

$ ./vs2022_menu_encryptor --decrypt "3e7988abb35c709f6f3e26e9666750f98bdbc21bcfe53ce9f53104648d890c70:a88eb89acfe2f145df49de1d2242eb44f8bc01a1c369413b80e0d703ef8151da:0d39fb97b4d8ee02cd925d5196c3084f12be39bb57fc23cee3edc0856c57aafa:b99b8a1497b5dc22a44f6f0f:58d737d12869fbc4936d36df"
Secret Message
```

## Build Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- Standard C++ library
- Linux: `/dev/urandom` for secure random generation
- Windows: WinCrypt API for secure random generation

## License

This project is provided as-is for educational and legitimate security purposes only. 
