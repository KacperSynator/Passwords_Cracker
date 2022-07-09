#pragma once

#include <vector>
#include <string>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <iostream>


class ThreadSharedData {
  public:
    struct CrackedPassPair {
      std::string hashed;
      std::string decoded;
    };

    void add_cracked_password(const std::string& hash, const std::string& pass);
    const CrackedPassPair get_last_cracked_password();
    bool load_dictionary(const std::string& dictionary_file);
    bool load_passwords(const std::string& passwords_file);
    int get_cracked_pass_count() {return cracked_passwords_.size();}
    bool is_cracked_pass_ready() {return password_added_;}
    std::vector<std::string>& get_dict() {return dict_;}
    std::vector<std::string>& get_passwords() {return passwords_;}


  private:
    bool read_file(const std::string& file, std::vector<std::string>& container);

    bool password_added_ = false;
    std::mutex cracked_pass_mut_;
    std::vector<std::string> dict_;
    std::vector<std::string> passwords_;
    std::vector<CrackedPassPair> cracked_passwords_;
};
