#include "utils.h"
#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>

// String utility implementations
std::string toUpperCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::string toLowerCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string reverseString(const std::string& str) {
    std::string result = str;
    std::reverse(result.begin(), result.end());
    return result;
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

// Input validation implementations
bool isValidNumber(const std::string& str) {
    std::istringstream iss(str);
    double d;
    iss >> std::noskipws >> d;
    return iss.eof() && !iss.fail();
}

int getValidInt(const std::string& prompt) {
    int value;
    while (true) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        
        std::istringstream iss(input);
        if (iss >> value) {
            return value;
        }
        std::cout << "Invalid input. Please enter a valid number." << std::endl;
    }
}

double getValidDouble(const std::string& prompt) {
    double value;
    while (true) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        
        std::istringstream iss(input);
        if (iss >> value) {
            return value;
        }
        std::cout << "Invalid input. Please enter a valid number." << std::endl;
    }
}

// Display utility implementations
void clearScreen() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

void pauseScreen() {
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void printHeader(const std::string& title) {
    printSeparator('=', title.length() + 4);
    std::cout << "  " << title << std::endl;
    printSeparator('=', title.length() + 4);
}

void printSeparator(char ch, int length) {
    std::cout << std::string(length, ch) << std::endl;
}