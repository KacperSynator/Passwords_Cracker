#pragma once

#include <condition_variable>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <algorithm>
#include <iomanip>

#include "inc/password_type_enum.h"
#include "inc/string_utils.h"
#include "inc/thread_shared_data.h"

class PasswordThread {
   public:
    PasswordThread() = delete;
    PasswordThread(const PasswordThread&) = delete;
    PasswordThread& operator=(const PasswordThread&) = delete;

    explicit PasswordThread(const PasswordType& type, const std::shared_ptr<ThreadSharedData>& tsd);
    ~PasswordThread() { if (thread_.joinable()) thread_.join(); }
    static void quit();
    static void stats();

   private:
    void handle_cracked_password(const std::string& hash, const std::string& decoded);
    void check_generated_password(const std::string& gen_pass);
    void check_generated_passwords(const std::vector<std::string>& gen_passes);
    void print_stats();
    // Thread functions
    void password_consumer();
    void numeric_passwords();
    void one_word_passwords(const std::function<const std::string(const std::string&)> transform_func);

    inline static bool quit_ = false;
    inline static bool stats_ = false;
    inline static std::mutex pass_cracked_mut_;
    inline static std::condition_variable pass_cracked_cv_;
    std::thread thread_;
    std::shared_ptr<ThreadSharedData> tsd_;
};
