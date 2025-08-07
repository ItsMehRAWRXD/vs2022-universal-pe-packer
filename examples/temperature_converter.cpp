// Example: Temperature Converter Tool
// This shows how to create a new tool following the established patterns

#include <iostream>
#include <string>
#include <iomanip>

class TemperatureConverter {
private:
    double celsius, fahrenheit, kelvin;
    
    void celsiusToOthers(double c) {
        celsius = c;
        fahrenheit = (c * 9/5) + 32;
        kelvin = c + 273.15;
    }
    
    void fahrenheitToOthers(double f) {
        fahrenheit = f;
        celsius = (f - 32) * 5/9;
        kelvin = celsius + 273.15;
    }
    
    void kelvinToOthers(double k) {
        kelvin = k;
        celsius = k - 273.15;
        fahrenheit = (celsius * 9/5) + 32;
    }
    
public:
    void run() {
        while (true) {
            std::cout << "\n=== Temperature Converter ===" << std::endl;
            std::cout << "1. Celsius to Fahrenheit/Kelvin" << std::endl;
            std::cout << "2. Fahrenheit to Celsius/Kelvin" << std::endl;
            std::cout << "3. Kelvin to Celsius/Fahrenheit" << std::endl;
            std::cout << "4. Back to Main Menu" << std::endl;
            
            int choice;
            std::cout << "Choose an option: ";
            std::cin >> choice;
            
            switch (choice) {
                case 1: {
                    double c;
                    std::cout << "Enter temperature in Celsius: ";
                    std::cin >> c;
                    celsiusToOthers(c);
                    std::cout << std::fixed << std::setprecision(2);
                    std::cout << c << "°C = " << fahrenheit << "°F = " << kelvin << "K" << std::endl;
                    break;
                }
                case 2: {
                    double f;
                    std::cout << "Enter temperature in Fahrenheit: ";
                    std::cin >> f;
                    fahrenheitToOthers(f);
                    std::cout << std::fixed << std::setprecision(2);
                    std::cout << f << "°F = " << celsius << "°C = " << kelvin << "K" << std::endl;
                    break;
                }
                case 3: {
                    double k;
                    std::cout << "Enter temperature in Kelvin: ";
                    std::cin >> k;
                    kelvinToOthers(k);
                    std::cout << std::fixed << std::setprecision(2);
                    std::cout << k << "K = " << celsius << "°C = " << fahrenheit << "°F" << std::endl;
                    break;
                }
                case 4:
                    return;
                default:
                    std::cout << "Invalid option!" << std::endl;
            }
        }
    }
};

// Example usage:
// int main() {
//     TemperatureConverter converter;
//     converter.run();
//     return 0;
// }