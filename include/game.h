#pragma once
#include "utils.h"
#include <random>

class Game : public BaseTool {
private:
    std::mt19937 rng;
    int secretNumber;
    int attempts;
    int maxAttempts;
    
    void generateNewNumber();
    void showRules();
    bool makeGuess(int guess);
    void showStatistics();
    void playGame();
    
public:
    Game() : rng(std::random_device{}()), attempts(0), maxAttempts(10) {
        generateNewNumber();
    }
    void run() override;
};