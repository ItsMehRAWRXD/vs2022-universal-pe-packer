# ChatGPT Integration Guide

## Overview

Your C++ AI Development Environment now includes full ChatGPT integration! You can chat with ChatGPT, ask coding questions, generate code, and debug issues directly from your development environment.

## Features

### 1. **Chat with ChatGPT**
- Direct conversation with ChatGPT
- Real-time responses
- Conversation history tracking

### 2. **Code Assistance**
- Ask questions about your code
- Get explanations and suggestions
- Debug help with error messages

### 3. **Code Generation**
- Generate code from descriptions
- Support for multiple languages (C++, Python, JavaScript, etc.)
- Template generation

### 4. **Debugging Help**
- Paste your code and error messages
- Get detailed debugging assistance
- Code optimization suggestions

## Setup

### 1. **Install Dependencies**
```bash
./setup.sh
```

This will install:
- CURL library for API communication
- SSL libraries for secure connections
- Build tools and CMake

### 2. **Get OpenAI API Key**
1. Go to [OpenAI API Keys](https://platform.openai.com/api-keys)
2. Sign in or create an account
3. Click "Create new secret key"
4. Copy the API key (starts with `sk-`)

### 3. **Configure API Key**
1. Run your development environment: `cd build && ./main`
2. Choose option 5: "ChatGPT Integration"
3. Choose option 5: "Configure API Key"
4. Enter your OpenAI API key
5. Choose 'y' to save it to file

## Usage

### **Accessing ChatGPT Integration**
1. Run the program: `cd build && ./main`
2. Choose option 5: "ChatGPT Integration"
3. Select your desired feature

### **Available Options**

#### 1. **Chat with ChatGPT**
- Direct conversation mode
- Type 'quit' or 'exit' to return to menu
- Full conversation history

#### 2. **Ask Code Question**
- Paste your code (type 'END' when done)
- Ask specific questions
- Get detailed explanations

#### 3. **Generate Code**
- Describe what you want to build
- Choose programming language
- Get complete code examples

#### 4. **Debug Code**
- Paste your problematic code
- Include error messages
- Get debugging assistance

#### 5. **Configure API Key**
- Set or update your OpenAI API key
- Save key to file for future use

#### 6. **View Chat History**
- See all previous conversations
- Review past questions and answers

#### 7. **Save Conversation**
- Export conversations to text files
- Keep records of coding sessions

## Example Usage

### **Code Question Example**
```
You: Here's my C++ code:
```cpp
int main() {
    int x = 5;
    std::cout << "Value: " << x << std::endl;
    return 0;
}
```

Question: How can I make this more robust?

ChatGPT: Here are several ways to make your code more robust:
1. Add input validation
2. Use proper error handling
3. Add comments for clarity
4. Consider using const where appropriate
...
```

### **Code Generation Example**
```
Description: Create a simple calculator that can add, subtract, multiply, and divide
Language: cpp

ChatGPT: Here's a simple calculator in C++:
```cpp
#include <iostream>
using namespace std;

int main() {
    double num1, num2;
    char operation;
    
    cout << "Enter first number: ";
    cin >> num1;
    
    cout << "Enter operation (+, -, *, /): ";
    cin >> operation;
    
    cout << "Enter second number: ";
    cin >> num2;
    
    switch(operation) {
        case '+': cout << "Result: " << num1 + num2; break;
        case '-': cout << "Result: " << num1 - num2; break;
        case '*': cout << "Result: " << num1 * num2; break;
        case '/': 
            if(num2 != 0) cout << "Result: " << num1 / num2;
            else cout << "Error: Division by zero!";
            break;
        default: cout << "Invalid operation!";
    }
    
    return 0;
}
```
```

## API Key Security

### **Storing Your API Key**
- The API key is saved locally in `chatgpt_api_key.txt`
- Keep this file secure and don't share it
- Consider adding it to `.gitignore` if using version control

### **API Usage Costs**
- OpenAI charges per API call
- GPT-3.5-turbo is relatively inexpensive
- Monitor your usage at [OpenAI Usage](https://platform.openai.com/usage)

## Troubleshooting

### **Common Issues**

#### 1. **"API key not configured"**
- Make sure you've set your API key
- Check that the key file exists and is readable
- Verify the key format (should start with `sk-`)

#### 2. **"Could not initialize CURL"**
- Install CURL library: `sudo apt-get install libcurl4-openssl-dev`
- Run `./setup.sh` to install all dependencies

#### 3. **"Error: Could not parse response"**
- Check your internet connection
- Verify your API key is valid
- Try again (temporary API issues)

#### 4. **Build errors with CURL**
- Make sure CURL is installed
- Check CMake configuration
- Run `./setup.sh` to install dependencies

### **Getting Help**
1. Check this documentation
2. Look at the troubleshooting guide
3. When online, ask the AI assistant for help

## Advanced Features

### **Custom Prompts**
You can modify the prompts in the source code to get more specific responses:

```cpp
// In chatgpt.cpp, modify these functions:
std::string ChatGPTClient::sendCodeQuestion(const std::string& code, const std::string& question) {
    std::string message = "Here's my code:\n```\n" + code + "\n```\n\nQuestion: " + question;
    return sendMessage(message);
}
```

### **Model Selection**
You can change the AI model by modifying the JSON payload:

```cpp
// Change from gpt-3.5-turbo to gpt-4 (requires different API access)
ss << "\"model\": \"gpt-4\",";
```

### **Response Length**
Adjust the `max_tokens` parameter to get longer or shorter responses:

```cpp
ss << "\"max_tokens\": 2000,";  // Increase for longer responses
```

## Best Practices

1. **Be Specific** - The more specific your questions, the better the answers
2. **Include Context** - Provide relevant code and error messages
3. **Review Responses** - Always review generated code before using it
4. **Save Important Conversations** - Use the save feature for valuable discussions
5. **Monitor Usage** - Keep track of your API usage to manage costs

## Integration with Other Tools

The ChatGPT integration works seamlessly with your other development tools:

- **Calculator** - Get help with complex calculations
- **Assembly Development** - Ask for MASM code examples
- **String Utilities** - Get help with text processing
- **File Operations** - Generate file handling code

## Next Steps

1. **Set up your API key** and try the basic chat
2. **Experiment with code questions** using your existing projects
3. **Generate code** for new features you want to add
4. **Use debugging help** when you encounter issues
5. **Save conversations** for future reference

Enjoy your enhanced development environment with AI assistance!