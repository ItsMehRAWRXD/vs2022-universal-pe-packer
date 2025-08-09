#include "game.h"
#include <iostream>

void Game::run() {
    while (true) {
        clearScreen();
        printHeader("Number Guessing Game");
        
        std::cout << "1. Start New Game" << std::endl;
        std::cout << "2. Show Rules" << std::endl;
        std::cout << "3. Show Statistics" << std::endl;
        std::cout << "4. Back to Main Menu" << std::endl;
        
        int choice = getValidInt("Choose an option: ");
        
        switch (choice) {
            case 1:
                playGame();
                break;
            case 2:
                showRules();
                break;
            case 3:
                showStatistics();
                break;
            case 4:
                return;
            default:
                std::cout << "Invalid option!" << std::endl;
        }
        pauseScreen();
    }
}

void Game::playGame() {
    generateNewNumber();
    attempts = 0;
    
    printHeader("Number Guessing Game");
    std::cout << "I'm thinking of a number between 1 and 100!" << std::endl;
    std::cout << "You have " << maxAttempts << " attempts to guess it." << std::endl;
    
    while (attempts < maxAttempts) {
        attempts++;
        std::cout << "\nAttempt " << attempts << "/" << maxAttempts << std::endl;
        
        int guess = getValidInt("Enter your guess: ");
        
        if (makeGuess(guess)) {
            std::cout << "\n🎉 Congratulations! You guessed it in " << attempts << " attempts!" << std::endl;
            return;
        }
    }
    
    std::cout << "\n😔 Game Over! The number was " << secretNumber << std::endl;
}

void Game::generateNewNumber() {
    std::uniform_int_distribution<int> dist(1, 100);
    secretNumber = dist(rng);
}

void Game::showRules() {
    printHeader("Game Rules");
    std::cout << "1. I will think of a random number between 1 and 100" << std::endl;
    std::cout << "2. You have " << maxAttempts << " attempts to guess it" << std::endl;
    std::cout << "3. After each guess, I'll tell you if your guess is:" << std::endl;
    std::cout << "   - Too high (try a lower number)" << std::endl;
    std::cout << "   - Too low (try a higher number)" << std::endl;
    std::cout << "   - Correct! (you win!)" << std::endl;
    std::cout << "4. Try to guess the number in as few attempts as possible!" << std::endl;
}

bool Game::makeGuess(int guess) {
    if (guess < 1 || guess > 100) {
        std::cout << "Please enter a number between 1 and 100!" << std::endl;
        attempts--; // Don't count invalid guesses
        return false;
    }
    
    if (guess == secretNumber) {
        return true;
    } else if (guess < secretNumber) {
        std::cout << "Too low! Try a higher number." << std::endl;
    } else {
        std::cout << "Too high! Try a lower number." << std::endl;
    }
    
    return false;
}

void Game::showStatistics() {
    printHeader("Game Statistics");
    std::cout << "Current game:" << std::endl;
    std::cout << "- Secret number: " << secretNumber << std::endl;
    std::cout << "- Attempts used: " << attempts << "/" << maxAttempts << std::endl;
    std::cout << "- Attempts remaining: " << (maxAttempts - attempts) << std::endl;
}