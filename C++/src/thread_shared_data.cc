#include "inc/thread_shared_data.h"

bool ThreadSharedData::read_file(const std::string& file,
                                 std::vector<std::string>& container) {
    std::ifstream fs(file);
    std::string s;

    if (!fs.is_open()) return false;

    while (fs >> s) container.emplace_back(s);

    return true;
}

bool ThreadSharedData::load_dictionary(const std::string& dictionary_file) {
    return read_file(dictionary_file, dict_);
}

bool ThreadSharedData::load_passwords(const std::string& passwords_file_) {
    return read_file(passwords_file_, passwords_);
}

void ThreadSharedData::add_cracked_password(const std::string& hash, const std::string& pass) {
    std::lock_guard lg(cracked_pass_mut_);
    password_added_ = true;
    cracked_passwords_.emplace_back(CrackedPassPair{hash, pass});
}

const ThreadSharedData::CrackedPassPair ThreadSharedData::get_last_cracked_password() {
    std::lock_guard lg(cracked_pass_mut_);
    password_added_ = false;
    return cracked_passwords_.back();
}
