#pragma once
#include <string>
#include <iostream>

// Base class for all tools
class BaseTool {
public:
    virtual ~BaseTool() = default;
    virtual void run() = 0;
};

// String utility functions
std::string toUpperCase(const std::string& str);
std::string toLowerCase(const std::string& str);
std::string reverseString(const std::string& str);
std::string trim(const std::string& str);

// Input validation functions
bool isValidNumber(const std::string& str);
int getValidInt(const std::string& prompt);
double getValidDouble(const std::string& prompt);

// Display utilities
void clearScreen();
void pauseScreen();
void printHeader(const std::string& title);
void printSeparator(char ch = '-', int length = 50);