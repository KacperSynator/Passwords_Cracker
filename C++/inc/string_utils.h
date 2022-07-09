#pragma once

#include <string>
#include <algorithm>

#include <openssl/md5.h>


class StringUtils {
  public:
    static const std::string md5_hash(const std::string& input);
    static const std::string to_upper(const std::string& input);
    static const std::string to_lower(const std::string& input);
    static const std::string first_upper(const std::string& input);
};
