#include "calculator.h"
#include <cmath>
#include <iomanip>

void Calculator::run() {
    while (true) {
        clearScreen();
        printHeader("Advanced Calculator");
        
        std::cout << "1. Basic Operations (+, -, *, /)" << std::endl;
        std::cout << "2. Power and Square Root" << std::endl;
        std::cout << "3. Memory Operations" << std::endl;
        std::cout << "4. View History" << std::endl;
        std::cout << "5. Clear History" << std::endl;
        std::cout << "6. Back to Main Menu" << std::endl;
        
        int choice = getValidInt("Choose an option: ");
        
        switch (choice) {
            case 1:
                basicOperations();
                break;
            case 2:
                advancedOperations();
                break;
            case 3:
                memoryOperations();
                break;
            case 4:
                showHistory();
                break;
            case 5:
                clearHistory();
                break;
            case 6:
                return;
            default:
                std::cout << "Invalid option!" << std::endl;
        }
        pauseScreen();
    }
}

void Calculator::basicOperations() {
    printHeader("Basic Operations");
    
    double a = getValidDouble("Enter first number: ");
    double b = getValidDouble("Enter second number: ");
    
    std::cout << "\nResults:" << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << a << " + " << b << " = " << add(a, b) << std::endl;
    std::cout << a << " - " << b << " = " << subtract(a, b) << std::endl;
    std::cout << a << " * " << b << " = " << multiply(a, b) << std::endl;
    
    if (b != 0) {
        std::cout << a << " / " << b << " = " << divide(a, b) << std::endl;
    } else {
        std::cout << "Division by zero is not allowed!" << std::endl;
    }
    
    // Save results to history
    history.push_back(add(a, b));
    history.push_back(subtract(a, b));
    history.push_back(multiply(a, b));
    if (b != 0) history.push_back(divide(a, b));
}

void Calculator::advancedOperations() {
    printHeader("Advanced Operations");
    
    double base = getValidDouble("Enter base number: ");
    double exponent = getValidDouble("Enter exponent: ");
    
    std::cout << "\nResults:" << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << base << " ^ " << exponent << " = " << power(base, exponent) << std::endl;
    std::cout << "√" << base << " = " << squareRoot(base) << std::endl;
    
    // Save to history
    history.push_back(power(base, exponent));
    history.push_back(squareRoot(base));
}

void Calculator::memoryOperations() {
    printHeader("Memory Operations");
    
    std::cout << "Current memory value: " << memory << std::endl;
    std::cout << "1. Save to memory" << std::endl;
    std::cout << "2. Recall from memory" << std::endl;
    std::cout << "3. Clear memory" << std::endl;
    
    int choice = getValidInt("Choose option: ");
    
    switch (choice) {
        case 1:
            memory = getValidDouble("Enter value to save: ");
            std::cout << "Value saved to memory!" << std::endl;
            break;
        case 2:
            std::cout << "Memory value: " << memory << std::endl;
            break;
        case 3:
            memory = 0.0;
            std::cout << "Memory cleared!" << std::endl;
            break;
    }
}

void Calculator::showHistory() {
    printHeader("Calculation History");
    
    if (history.empty()) {
        std::cout << "No calculations in history." << std::endl;
        return;
    }
    
    for (size_t i = 0; i < history.size(); ++i) {
        std::cout << (i + 1) << ". " << history[i] << std::endl;
    }
}

void Calculator::clearHistory() {
    history.clear();
    std::cout << "History cleared!" << std::endl;
}

// Mathematical operation implementations
double Calculator::add(double a, double b) { return a + b; }
double Calculator::subtract(double a, double b) { return a - b; }
double Calculator::multiply(double a, double b) { return a * b; }
double Calculator::divide(double a, double b) { return b != 0 ? a / b : 0; }
double Calculator::power(double base, double exponent) { return std::pow(base, exponent); }
double Calculator::squareRoot(double value) { return std::sqrt(value); }