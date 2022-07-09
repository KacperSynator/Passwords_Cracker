#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <csignal>
#include <iostream>
#include <memory>

#include "inc/thread_shared_data.h"
#include "inc/password_thread.h"
#include "inc/password_type_enum.h"


const auto kDefaultDictionary("inside_pro_mini.dic");
const std::filesystem::path kDataDirPath{DATA_DIR_PATH};


class PasswordCracker {
  public:
    PasswordCracker() = default;
    PasswordCracker(const PasswordCracker&) = delete;
    PasswordCracker& operator= (const PasswordCracker&) = delete;

    bool init(const std::string& passwords_file,
              const std::string& dict_file = kDefaultDictionary);
    static void quit(int signal);
    static void stats(int signal);
    void main_loop();

  private:
  void create_threads();
  void setup_signals();

    std::vector<std::unique_ptr<PasswordThread>> threads_;
    std::shared_ptr<ThreadSharedData> tsd_;
};
