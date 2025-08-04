#include <iostream> 
#include <fstream> 
#include <vector> 
#include <string> 

using namespace std; 

int main() { 
    try {
        cout << "PE Packer Ready!" << endl; 
        cout << "Press any key to continue..." << endl;
        cin.get();
        return 0; 
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
} 
