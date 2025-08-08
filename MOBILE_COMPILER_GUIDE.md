# Mobile Compiler Service - VS2022 Menu Encryptor Suite

## Overview

The Mobile Compiler Service provides cloud-based code compilation capabilities for mobile devices. It integrates multiple online compiler services and offers our own secure backend for code execution.

## Features

### 🚀 Multiple Compiler Backends
- **Godbolt Compiler Explorer**: Free, no auth required
- **JDoodle API**: 200 requests/min with API key
- **Wandbox**: Free Japanese compiler service
- **Judge0**: Professional compiler API
- **Custom Backend**: Our secure, sandboxed compiler

### 📱 Mobile Optimizations
- Lightweight API responses
- Truncated output for mobile screens
- Fast compilation with caching
- Progressive web app support
- Offline code storage

### 🔒 Security Features
- Sandboxed execution environment
- Resource limits (CPU, memory, time)
- Network isolation for code execution
- Rate limiting per user
- Input sanitization

## API Endpoints

### 1. Submit Compilation
```http
POST /api/compile
Content-Type: application/json

{
    "language": "c++",
    "code": "int main() { return 0; }",
    "input": "",
    "flags": "-O2",
    "provider": "auto"
}
```

### 2. Mobile-Optimized Compilation
```http
POST /api/compile/mobile
Content-Type: application/json

{
    "language": "python",
    "code": "print('Hello')"
}
```

### 3. Get Available Compilers
```http
GET /api/compilers
```

### 4. Get Compilation Result
```http
GET /api/compile/{requestId}
```

### 5. Batch Compilation
```http
POST /api/compile/batch
Content-Type: application/json

{
    "userId": "mobile-user-123",
    "requests": [
        {
            "language": "c++",
            "code": "...",
            "provider": "godbolt"
        },
        {
            "language": "python",
            "code": "...",
            "provider": "custom"
        }
    ]
}
```

## Supported Languages

| Language | File Extension | Compilers Available |
|----------|---------------|-------------------|
| C++ | .cpp | g++, clang++ |
| C | .c | gcc, clang |
| Python | .py | python3 |
| Java | .java | javac |
| JavaScript | .js | node |
| Rust | .rs | rustc |
| Go | .go | go |
| Assembly | .asm | nasm, gas |

## Mobile App Integration

### Web App
Access the mobile compiler at: `http://your-server:8081/`

### Native App Integration

#### iOS (Swift)
```swift
import Foundation

class CompilerService {
    let baseURL = "http://your-server:8081/api"
    
    func compile(code: String, language: String) async throws -> CompilationResult {
        let url = URL(string: "\(baseURL)/compile/mobile")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = [
            "language": language,
            "code": code
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(CompilationResult.self, from: data)
    }
}
```

#### Android (Kotlin)
```kotlin
class CompilerService(private val context: Context) {
    private val baseUrl = "http://your-server:8081/api"
    
    suspend fun compile(code: String, language: String): CompilationResult {
        return withContext(Dispatchers.IO) {
            val client = OkHttpClient()
            val json = JSONObject().apply {
                put("language", language)
                put("code", code)
            }
            
            val request = Request.Builder()
                .url("$baseUrl/compile/mobile")
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()
            
            client.newCall(request).execute().use { response ->
                val result = JSONObject(response.body!!.string())
                CompilationResult(
                    success = result.getBoolean("success"),
                    output = result.getString("output"),
                    error = result.optString("error", "")
                )
            }
        }
    }
}
```

## Building the Service

### Prerequisites
```bash
# Install dependencies
sudo apt-get install g++ cmake libcurl4-openssl-dev

# Install C++ libraries
vcpkg install cpp-httplib nlohmann-json websocketpp
```

### Compile
```bash
g++ -std=c++17 MobileCompilerService.cpp -o mobile-compiler \
    -lcurl -lpthread -lstdc++fs \
    -I/path/to/vcpkg/installed/include \
    -L/path/to/vcpkg/installed/lib
```

### Docker Deployment
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    g++ \
    python3 \
    nodejs \
    golang \
    rustc \
    openjdk-11-jdk \
    firejail \
    curl \
    cmake

COPY mobile-compiler /app/
WORKDIR /app

EXPOSE 8081

CMD ["./mobile-compiler"]
```

## Configuration

### Environment Variables
```bash
# API Keys
export JDOODLE_API_KEY="your-key-here"
export JUDGE0_API_KEY="your-key-here"

# Service Configuration
export COMPILER_PORT=8081
export MAX_EXECUTION_TIME=5
export MAX_MEMORY_MB=512
export RATE_LIMIT_PER_MINUTE=50
```

### Custom Compiler Configuration
Edit `compiler_config.json`:
```json
{
    "compilers": {
        "c++": {
            "command": "g++ -std=c++17",
            "flags": ["-O2", "-Wall"],
            "timeout": 5
        },
        "python": {
            "command": "python3",
            "flags": [],
            "timeout": 10
        }
    }
}
```

## Security Considerations

1. **Code Execution Isolation**
   - Uses firejail on Linux for sandboxing
   - Network access disabled during execution
   - Resource limits enforced

2. **Rate Limiting**
   - 50 requests per minute per user
   - Automatic cooldown period
   - IP-based tracking for anonymous users

3. **Input Validation**
   - Code size limited to 50KB
   - Malicious pattern detection
   - Command injection prevention

## Usage Examples

### Basic Compilation
```javascript
// Mobile web app
const response = await fetch('http://localhost:8081/api/compile/mobile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        language: 'python',
        code: 'print("Hello from mobile!")'
    })
});

const result = await response.json();
console.log(result.output); // "Hello from mobile!"
```

### With Custom Flags
```javascript
const response = await fetch('http://localhost:8081/api/compile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        language: 'c++',
        code: '#include <iostream>\nint main() { std::cout << "Optimized!"; }',
        flags: '-O3 -march=native',
        provider: 'custom'
    })
});
```

### Share Code
```javascript
const response = await fetch('http://localhost:8081/api/share', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        language: 'rust',
        code: 'fn main() { println!("Shared Rust code"); }'
    })
});

const { shareUrl } = await response.json();
// shareUrl: "https://compile.vs2022.app/s/abc123"
```

## Performance Tips

1. **Use Mobile Endpoint**: The `/api/compile/mobile` endpoint is optimized for quick responses
2. **Choose Providers Wisely**: Custom backend is fastest, Godbolt is most feature-rich
3. **Cache Templates**: Store common code templates locally
4. **Batch Requests**: Use batch endpoint for multiple compilations

## Troubleshooting

### Common Issues

1. **Rate Limit Exceeded**
   - Wait 60 seconds before retrying
   - Consider using authenticated requests

2. **Compilation Timeout**
   - Optimize code for faster execution
   - Avoid infinite loops
   - Reduce input size

3. **Unsupported Language Features**
   - Check compiler version
   - Use standard language features
   - Avoid platform-specific code

## Future Enhancements

- [ ] WebAssembly support for client-side compilation
- [ ] Real-time collaborative coding
- [ ] Integration with GitHub Codespaces
- [ ] Support for more languages (Swift, Kotlin, etc.)
- [ ] AI-powered code suggestions
- [ ] Execution profiling and optimization hints

## Contributing

The Mobile Compiler Service is part of the VS2022 Menu Encryptor Suite. Contributions are welcome!

1. Add new compiler providers
2. Improve sandboxing security
3. Add language support
4. Optimize for mobile performance
5. Create native mobile SDKs