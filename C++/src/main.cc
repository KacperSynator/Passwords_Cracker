#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <csignal>

#include "inc/password_cracker.h"



int main(int argc, char* argv[]) {
    PasswordCracker pc;

    if (argc <= 1) {
        std::cout << "Passwords file not provided\n";
        return -1;
    } else if (argc > 2) {
        std::cout << "Loading given dictionary\n";
        if (!pc.init(argv[1], argv[2])) return -1;
    } else {
        if (!pc.init(argv[1])) return -1;
    }
    
}
