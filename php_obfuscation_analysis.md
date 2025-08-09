# PHP Obfuscation & Webshell Techniques Analysis

## Overview
This document analyzes various PHP obfuscation techniques and webshell implementations found in malicious scripts. These techniques are used to evade detection and maintain persistence on compromised web servers.

## File Disguise Techniques

### 1. GIF Header Spoofing
Multiple files use fake GIF headers to disguise PHP payloads:
- `iam.gif`: Uses `GIF89aGiam` header
- `aa.php`: Uses `GÝF89;a` header (corrupted GIF signature)

**Detection**: Look for GIF magic bytes followed by PHP opening tags.

## Obfuscation Methods

### 1. Multi-Layer Encoding (iam.gif)
```php
eval(gzinflate(str_rot13(base64_decode('...'))));
```
- **Layer 1**: Base64 encoding
- **Layer 2**: ROT13 cipher
- **Layer 3**: gzinflate decompression
- **Layer 4**: eval() execution

### 2. Variable Variable Names (aa.php)
```php
$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');
$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000000{3}.$OOO000000{5};
```
- Uses confusing variable names (O's and 0's)
- Builds function names dynamically from character arrays
- URL-encoded function name construction

### 3. Direct System Commands (abc.php)
```php
system("echo x> index.html");
system("cp sittir.php ../../../../../../cache/sok.php");
system("rm -rf php-ofc-library/ofc_upload_image.php");
```
- Simple but effective file manipulation
- Directory traversal attacks
- File placement in multiple locations

## Common Patterns

### Authentication Bypass
- MD5 password hashing
- Session-based authentication
- User-Agent filtering (blocking search engines)

### File Operations
- File upload/download capabilities
- Directory traversal
- File system manipulation
- Image viewing functionality

### Network Operations
- UDP flooding capabilities
- Socket programming with `fsockopen`
- Packet generation and transmission

## Advanced Features

### 1. Comprehensive Webshell (ultimate_php_webshell.php)
- Command execution via multiple methods
- File manager interface
- Database connectivity
- Network tools integration
- Process management

### 2. DoS Capabilities
- UDP flood implementation
- Packet size optimization (65KB)
- Duration-based attacks
- Statistics reporting

## Evasion Techniques

### 1. Error Suppression
```php
@error_reporting(0);
@ini_set('display_errors', 0);
@set_time_limit(0);
```

### 2. Function Obfuscation
- Dynamic function name construction
- Character array manipulation
- URL encoding for function names

### 3. String Obfuscation
- Multiple encoding layers
- Character substitution
- Binary data embedding

## Detection Signatures

### 1. Suspicious Headers
- GIF headers followed by PHP code
- Malformed GIF signatures
- Binary data in text files

### 2. Obfuscation Patterns
- Multiple eval() statements
- Base64/ROT13/gzinflate combinations
- Confusing variable naming patterns
- URL-encoded strings for function names

### 3. Malicious Functions
- `system()`, `exec()`, `shell_exec()`
- `eval()`, `assert()`, `preg_replace()`
- `fsockopen()` for network operations
- File manipulation functions

## Mitigation Strategies

### 1. Server Configuration
```ini
safe_mode = on
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
allow_url_fopen = off
allow_url_include = off
```

### 2. File Monitoring
- Monitor for suspicious file extensions
- Check for GIF files with PHP content
- Scan for obfuscated code patterns
- Monitor system command execution

### 3. Network Security
- Block UDP flooding patterns
- Monitor for unusual socket connections
- Implement rate limiting
- Log suspicious network activity

## Payload Analysis Results

### aa.php Decoded String
The URL-encoded string `%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64` decodes to build PHP function names dynamically, creating a sophisticated obfuscation layer that constructs executable code at runtime.

### Attack Vector Summary
1. **File Upload**: Disguised as image files
2. **Persistence**: Multiple file placement strategies
3. **Evasion**: Multi-layer obfuscation
4. **Functionality**: Full remote administration capabilities
5. **Network**: DoS and flooding capabilities

This analysis provides insights into modern PHP webshell techniques and their countermeasures.