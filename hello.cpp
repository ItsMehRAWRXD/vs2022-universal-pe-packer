#include <iostream>
using namespace std;

int main() {
    cout << "Hello! Welcome to C++ Programming!" << endl;
    cout << "What would you like to build today?" << endl;
    
    string name;
    cout << "Enter your name: ";
    getline(cin, name);
    
    cout << "Nice to meet you, " << name << "!" << endl;
    cout << "Let's start coding together!" << endl;
    
    return 0;
}