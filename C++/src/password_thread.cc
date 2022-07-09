#include "inc/password_thread.h"

PasswordThread::PasswordThread(const PasswordType& type, const std::shared_ptr<ThreadSharedData>& tsd) {
    tsd_ = tsd;
    switch (type) {
        case PasswordType::kConsumer: {
            thread_ = std::thread(&PasswordThread::password_consumer, this);
            break;
        }

        case PasswordType::kNumeric: {
            thread_ = std::thread(&PasswordThread::numeric_passwords, this);
            break;
        }

        case PasswordType::kAllLower: {
            thread_ = std::thread(&PasswordThread::one_word_passwords, this, StringUtils::to_lower);
            break;
        }

        case PasswordType::kAllUpper:{
            thread_ = std::thread(&PasswordThread::one_word_passwords, this, StringUtils::to_upper);
            break;
        }

        case PasswordType::kFirstUpper:{
            thread_ = std::thread(&PasswordThread::one_word_passwords, this, StringUtils::first_upper);
            break;
        }

        default:
            break;
    }
}

void PasswordThread::quit() {
    quit_ = true;
    std::unique_lock lg(pass_cracked_mut_);
    pass_cracked_cv_.notify_one();
}

void PasswordThread::stats() {
    stats_ = true;
    std::unique_lock lg(pass_cracked_mut_);
    pass_cracked_cv_.notify_one();
}

void PasswordThread::handle_cracked_password(const std::string& hash, const std::string& decoded) {
    tsd_->add_cracked_password(hash, decoded);
    std::lock_guard lg(pass_cracked_mut_);
    pass_cracked_cv_.notify_one();
    std::cout << "Password cracked: " << hash << " -> " << decoded << "\n";
}

void PasswordThread::check_generated_password(const std::string& gen_pass) {
    auto hashed_pass = StringUtils::md5_hash(gen_pass);
    for (const auto& pass : tsd_->get_passwords()) {
        if (pass == hashed_pass) {
            handle_cracked_password(pass, gen_pass);
        }
    }
}

void PasswordThread::check_generated_passwords(const std::vector<std::string>& gen_passes) {
    std::vector<ThreadSharedData::CrackedPassPair> passes;
    for (const auto& pass : gen_passes)
        passes.emplace_back(ThreadSharedData::CrackedPassPair{ StringUtils::md5_hash(pass), pass});
    for (const auto& pass : tsd_->get_passwords()) {
        for (const auto& pass_pair : passes) {
            if (pass == pass_pair.hashed) {
               handle_cracked_password(pass, pass_pair.decoded);
            }
        }
    }
}

void PasswordThread::print_stats() {
    auto passwords_count = tsd_->get_passwords().size();
    auto cracked_count = tsd_->get_cracked_pass_count();
    std::cout << "Stats -> cracked " << cracked_count << " of " << passwords_count << " "
              << std::fixed << std::setprecision(2)
              << static_cast<float>(cracked_count) / static_cast<float>(passwords_count) * 100 << "%\n";
}

void PasswordThread::password_consumer() {
    while (!quit_) {
        {
            std::unique_lock lg(pass_cracked_mut_);
            pass_cracked_cv_.wait(lg, [this]() {return quit_ || stats_ || tsd_->is_cracked_pass_ready();});
            if (stats_) {
                stats_ = false;
                print_stats();
                continue;
            }
            auto cracked_pass = tsd_->get_last_cracked_password();
            std::cout << "Consumer: Password cracked: " << cracked_pass.hashed
                      << " -> " << cracked_pass.decoded << "\n";
        }
    }
    print_stats();
}

void PasswordThread::numeric_passwords() {
    for (int i = 0; i <= std::numeric_limits<int>::max(); i++) {
        if (quit_) break;
        check_generated_password(std::to_string(i));
    }
}

void PasswordThread::one_word_passwords(const std::function<const std::string(const std::string&)> transform_func) {
    for (const auto& word : tsd_->get_dict()) {
        if (quit_) break;
        check_generated_password(transform_func(word));
    }
    for (int num = 0; num <= std::numeric_limits<int>::max(); num++) {
        if (quit_) break;
        auto str_num = std::to_string(num);
        for (const auto& word : tsd_->get_dict()) {
            check_generated_passwords(std::vector<std::string>{
                str_num + transform_func(word),
                          transform_func(word) + str_num,
                str_num + transform_func(word) + str_num
            });
        }
    }
}
