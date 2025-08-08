#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "Mother Lilith - Micro Compi (C++ CLI)\n";
    std::cout << "Usage: mother_lilith <command> [options]\n";
    std::cout << "Commands:\n";
    std::cout << "  add <git_url>      Add a GitHub repo\n";
    std::cout << "  list               List managed repos\n";
    std::cout << "  remove <git_url>   Remove a repo\n";
    std::cout << "  combine ...        Combine and build code\n";
    std::cout << "  run ...            Run a built binary\n";
    return 0;
}