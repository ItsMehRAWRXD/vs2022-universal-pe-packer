#pragma once
#include "utils.h"
#include <vector>

class Calculator : public BaseTool {
private:
    double memory;
    std::vector<double> history;
    
    double add(double a, double b);
    double subtract(double a, double b);
    double multiply(double a, double b);
    double divide(double a, double b);
    double power(double base, double exponent);
    double squareRoot(double value);
    
    void showHistory();
    void clearHistory();
    void saveToMemory(double value);
    double recallFromMemory();
    
    // Additional methods
    void basicOperations();
    void advancedOperations();
    void memoryOperations();
    
public:
    Calculator() : memory(0.0) {}
    void run() override;
};