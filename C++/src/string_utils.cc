#include "inc/string_utils.h"

const std::string StringUtils::md5_hash(const std::string& input) {

    char result[33];
    unsigned char digest[16];
    MD5_CTX ctx;
    MD5_Init(&ctx);

    MD5_Update(&ctx, input.c_str(), input.size());
    MD5_Final(digest, &ctx);

    for (int n = 0; n < 16; ++n)
        sprintf(&(result)[n * 2], "%02x", (unsigned int)digest[n]);

    return std::string(result);
}

const std::string StringUtils::to_upper(const std::string& input) {
    std::string result(input);
    std::transform(input.begin(), input.end(), result.begin(), ::toupper);
    return result;
}

const std::string StringUtils::to_lower(const std::string& input) {
    std::string result(input);
    std::transform(input.begin(), input.end(), result.begin(), ::tolower);
    return result;
}

const std::string StringUtils::first_upper(const std::string& input) {
    std::string result = to_lower(input);
    result[0] = ::toupper(result[0]);
    return result;
}
