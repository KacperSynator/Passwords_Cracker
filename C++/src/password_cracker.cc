#include "inc/password_cracker.h"

bool PasswordCracker::init(const std::string& passwords_file, const std::string& dict_file) {
    tsd_ = std::make_shared<ThreadSharedData>();
    if (!tsd_->load_dictionary(kDataDirPath / dict_file)) {
        std::cout << "Dictionary not found: " << kDataDirPath / dict_file << "\n";
        return false;
    }

    if (!tsd_->load_passwords(kDataDirPath / passwords_file)) {
        std::cout << "Passwords not found: " << kDataDirPath / passwords_file << "\n";
        return false;
    }

    create_threads();
    setup_signals();
    
    return true;
}

void PasswordCracker::create_threads() {
    threads_.emplace_back(std::make_unique<PasswordThread>(PasswordType::kNumeric, tsd_));
    threads_.emplace_back(std::make_unique<PasswordThread>(PasswordType::kConsumer, tsd_));
    threads_.emplace_back(std::make_unique<PasswordThread>(PasswordType::kAllLower, tsd_));
    threads_.emplace_back(std::make_unique<PasswordThread>(PasswordType::kAllUpper, tsd_));
    threads_.emplace_back(std::make_unique<PasswordThread>(PasswordType::kFirstUpper, tsd_));
}

void PasswordCracker::setup_signals() {
    std::signal(SIGINT, quit);
    std::signal(SIGUSR1, stats);
}

void PasswordCracker::quit(int signal) {
    std::cout << "Quit signal\n";
    PasswordThread::quit();
}

void PasswordCracker::stats(int signal) {
    std::cout << "Stats signal\n";
    PasswordThread::stats();
}
