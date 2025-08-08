# VS2022 Menu Encryptor - Multi-Platform Build Guide

## Overview

The VS2022 Menu Encryptor is now available in platform-specific versions optimized for:
- **Windows** (10/11) with native Win32 APIs
- **macOS** with Objective-C++ and native frameworks
- **Linux** with kernel features and system APIs
- **Android** with Java/JNI implementation

## Windows Build

### Requirements
- Visual Studio 2022
- Windows SDK 10.0.19041.0 or later
- C++20 compiler support

### Build Steps
```cmd
# Using Visual Studio Developer Command Prompt
cl /std:c++20 /EHsc VS2022_MenuEncryptor_Windows.cpp /Fe:VS2022MenuEncryptor_Windows.exe

# Or using CMake
cmake -B build_windows -G "Visual Studio 17 2022"
cmake --build build_windows --config Release
```

### Windows-Specific Features
- TPM hardware encryption support
- Windows Crypto API integration
- Registry persistence
- Anti-debugging with multiple techniques
- Clipboard monitoring
- Native file picker dialog
- Event log integration
- Sandbox/VM detection

## macOS Build

### Requirements
- Xcode 13+ 
- macOS 11.0+ SDK
- Command Line Tools

### Build Steps
```bash
# Compile with clang++
clang++ -std=c++20 -framework Foundation -framework Security \
        -framework AppKit -framework LocalAuthentication \
        -framework CoreWLAN -framework IOKit \
        VS2022_MenuEncryptor_macOS.mm -o VS2022MenuEncryptor_macOS

# Or using CMake
cmake -B build_macos -G Xcode
cmake --build build_macos --config Release
```

### macOS-Specific Features
- Secure Enclave encryption
- Touch ID authentication
- Keychain integration
- File system event monitoring
- Network interface monitoring
- Power management
- Native file picker
- Code signing validation

## Linux Build

### Requirements
- GCC 11+ or Clang 13+
- Linux kernel 5.0+
- Development libraries:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install build-essential libgtk-3-dev libsodium-dev \
                      libcap-dev libseccomp-dev libssl-dev

  # Fedora/RHEL
  sudo dnf install gcc-c++ gtk3-devel libsodium-devel \
                  libcap-devel libseccomp-devel openssl-devel
  ```

### Build Steps
```bash
# Compile with g++
g++ -std=c++20 VS2022_MenuEncryptor_Linux.cpp \
    -o VS2022MenuEncryptor_Linux \
    $(pkg-config --cflags --libs gtk+-3.0) \
    -lsodium -lcap -lseccomp -pthread -lstdc++fs

# Or using CMake
cmake -B build_linux
cmake --build build_linux --config Release
```

### Linux-Specific Features
- Kernel crypto API
- Memory-only files (memfd)
- inotify file monitoring
- Seccomp sandboxing
- Process capabilities
- Container detection
- systemd service integration
- GTK file picker

## Android Build

### Requirements
- Android Studio 2021.3+
- Android NDK r23+
- Android SDK 31+
- CMake 3.18+

### Project Structure
```
android/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/
│   │   │   │   └── com/itsmehrawrxd/vs2022encryptor/
│   │   │   │       └── VS2022MenuEncryptorActivity.java
│   │   │   ├── cpp/
│   │   │   │   └── VS2022_MenuEncryptor_Android_JNI.cpp
│   │   │   └── AndroidManifest.xml
│   │   └── CMakeLists.txt
│   └── build.gradle
└── settings.gradle
```

### Build Steps

1. **Create Android Project**
```bash
# Create project structure
mkdir -p android/app/src/main/java/com/itsmehrawrxd/vs2022encryptor
mkdir -p android/app/src/main/cpp

# Copy files
cp VS2022_MenuEncryptor_Android.java \
   android/app/src/main/java/com/itsmehrawrxd/vs2022encryptor/VS2022MenuEncryptorActivity.java
cp VS2022_MenuEncryptor_Android_JNI.cpp \
   android/app/src/main/cpp/
```

2. **CMakeLists.txt**
```cmake
cmake_minimum_required(VERSION 3.18.1)
project("vs2022encryptor")

add_library(vs2022encryptor SHARED
    VS2022_MenuEncryptor_Android_JNI.cpp)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(vs2022encryptor
    ${log-lib}
    ${android-lib})
```

3. **Build APK**
```bash
# Using Android Studio
# Build → Generate Signed Bundle/APK

# Using command line
./gradlew assembleRelease
```

### Android-Specific Features
- Hardware-backed encryption (Android Keystore)
- Fingerprint/biometric authentication
- Root detection
- Anti-debugging protection
- Encrypted storage (EncryptedFile/SharedPreferences)
- File access monitoring
- App integrity checks
- StrongBox support (Android 9+)

## Cross-Platform Compilation

### Using Docker

**Windows Container:**
```dockerfile
FROM mcr.microsoft.com/windows/servercore:ltsc2022
RUN powershell -Command \
    Invoke-WebRequest -Uri https://aka.ms/vs/17/release/vs_buildtools.exe -OutFile vs_buildtools.exe; \
    Start-Process -Wait -FilePath vs_buildtools.exe -ArgumentList '--quiet', '--wait', '--add', 'Microsoft.VisualStudio.Workload.VCTools'
COPY VS2022_MenuEncryptor_Windows.cpp .
RUN cl /std:c++20 /EHsc VS2022_MenuEncryptor_Windows.cpp
```

**Linux Container:**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    build-essential libgtk-3-dev libsodium-dev \
    libcap-dev libseccomp-dev
COPY VS2022_MenuEncryptor_Linux.cpp .
RUN g++ -std=c++20 VS2022_MenuEncryptor_Linux.cpp \
    -o VS2022MenuEncryptor_Linux \
    $(pkg-config --cflags --libs gtk+-3.0) \
    -lsodium -lcap -lseccomp -pthread
```

## Deployment

### Windows
- Sign with code signing certificate
- Create MSI installer using WiX Toolset
- Submit to Windows Store (optional)

### macOS
- Code sign with Apple Developer ID
- Notarize with Apple
- Create DMG installer
- Submit to Mac App Store (optional)

### Linux
- Create AppImage for universal distribution
- Build DEB package for Debian/Ubuntu
- Build RPM package for Fedora/RHEL
- Submit to Flathub (optional)

### Android
- Sign APK with release keystore
- Enable app bundle for Google Play
- ProGuard/R8 for code obfuscation
- Submit to Google Play Store

## Security Considerations

1. **Code Signing**: Always sign your binaries
2. **Anti-Tampering**: Enable integrity checks
3. **Obfuscation**: Use platform-specific obfuscators
4. **Updates**: Implement secure update mechanisms
5. **Permissions**: Request minimum required permissions

## Performance Optimization

### Compiler Flags
- **Windows**: `/O2 /GL /arch:AVX2`
- **macOS**: `-O3 -march=native`
- **Linux**: `-O3 -march=native -flto`
- **Android**: Enable ProGuard minification

### Platform-Specific Optimizations
- Use hardware acceleration where available
- Leverage platform-specific crypto APIs
- Optimize for target CPU architecture

## Testing

Run platform-specific tests:
```bash
# Windows
VS2022MenuEncryptor_Windows.exe --test

# macOS
./VS2022MenuEncryptor_macOS --test

# Linux
./VS2022MenuEncryptor_Linux --test

# Android
adb shell am instrument -w com.itsmehrawrxd.vs2022encryptor.test
```

## Distribution Channels

- **Windows**: Microsoft Store, GitHub Releases
- **macOS**: Mac App Store, Homebrew, GitHub Releases
- **Linux**: Snap Store, Flathub, AUR, GitHub Releases
- **Android**: Google Play Store, F-Droid, GitHub Releases

This multi-platform approach ensures maximum reach and optimal performance across all major operating systems!