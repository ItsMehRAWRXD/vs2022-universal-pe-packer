# Troubleshooting Guide

## 🚨 Common Problems and Solutions

### Build Issues

#### Problem: "File not found" during build
```
fatal error: 'utils.h' file not found
```

**Solution:**
- Check that all header files are in the `include/` directory
- Verify `CMakeLists.txt` includes the correct paths
- Make sure you're running `./build.sh` from the project root

#### Problem: "Undefined reference" errors
```
undefined reference to 'function_name'
```

**Solution:**
- Check that the function is declared in the header file
- Ensure the function is implemented in the source file
- Verify the source file is included in `src/CMakeLists.txt`

#### Problem: CMake configuration fails
```
CMake Error: The source directory does not appear to contain CMakeLists.txt
```

**Solution:**
- Make sure you're in the correct directory
- Verify `CMakeLists.txt` exists in the project root
- Check file permissions: `chmod +x build.sh`

### Runtime Issues

#### Problem: Program crashes on startup
```
Segmentation fault (core dumped)
```

**Solution:**
- Check for null pointer access
- Verify all required files exist
- Add debug output to identify the crash location
- Use try-catch blocks around risky operations

#### Problem: Invalid input causes crashes
```
Program hangs or crashes when entering text
```

**Solution:**
- Always use `getValidInt()` and `getValidDouble()`
- Clear input buffer with `std::cin.ignore()`
- Add input validation before processing

#### Problem: Menu doesn't work properly
```
Menu shows wrong options or doesn't respond
```

**Solution:**
- Check switch statement cases match menu options
- Verify input is being read correctly
- Add debug output to see what choice was selected

### File Operation Issues

#### Problem: Can't read/write files
```
Error: Could not open file!
```

**Solution:**
- Check file path is correct
- Verify file permissions
- Use absolute paths if needed
- Check if directory exists

#### Problem: File content is corrupted
```
File contains garbage or wrong data
```

**Solution:**
- Check file opening mode (text vs binary)
- Verify data is being written correctly
- Close files properly after use
- Check for buffer overflow

## 🔧 Debugging Techniques

### 1. Add Debug Output
```cpp
std::cout << "DEBUG: Entering function with value = " << value << std::endl;
```

### 2. Check File Operations
```cpp
std::ifstream file("test.txt");
if (!file.is_open()) {
    std::cout << "ERROR: Could not open test.txt" << std::endl;
    return;
}
```

### 3. Validate Input
```cpp
if (number < 0 || number > 100) {
    std::cout << "ERROR: Number out of range: " << number << std::endl;
    return;
}
```

### 4. Use Try-Catch
```cpp
try {
    // Risky operation
    riskyFunction();
} catch (const std::exception& e) {
    std::cout << "ERROR: " << e.what() << std::endl;
}
```

## 🛠️ Emergency Fixes

### Complete Rebuild
```bash
# Remove all build files and rebuild
rm -rf build
./build.sh
```

### Check File Structure
```bash
# Verify all required files exist
ls -la include/
ls -la src/
ls -la CMakeLists.txt
```

### Test Individual Components
```bash
# Test just the main program
cd build
./main
```

### Check Compiler Version
```bash
# Verify C++ compiler
g++ --version
cmake --version
```

## 📋 Common Error Messages

| Error Message | Likely Cause | Solution |
|---------------|--------------|----------|
| `'function' was not declared` | Missing header include | Add `#include "header.h"` |
| `undefined reference` | Missing implementation | Check source file exists |
| `segmentation fault` | Null pointer access | Add null checks |
| `file not found` | Wrong path | Check file location |
| `invalid input` | Input validation | Use validation functions |

## 🎯 Prevention Tips

1. **Always validate input** before using it
2. **Check file operations** for success
3. **Use meaningful variable names**
4. **Add comments** for complex logic
5. **Test incrementally** - don't write everything at once
6. **Keep backups** of working code

## 📞 Getting Help

### When Online (with AI):
1. Describe the exact error message
2. Show the relevant code
3. Explain what you were trying to do
4. Mention what you've already tried

### When Offline:
1. Check this troubleshooting guide
2. Look at the examples in `examples/`
3. Review the coding guide in `docs/CODING_GUIDE.md`
4. Add debug output to isolate the problem

## 🔍 Diagnostic Commands

```bash
# Check if program exists
ls -la build/main

# Check file permissions
ls -la *.cpp *.h

# Find specific text in files
grep -r "function_name" src/

# Check disk space
df -h

# Check memory usage
free -h
```

Remember: Most problems can be solved by adding debug output and checking each step carefully!