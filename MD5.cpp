#include <iostream>
#include <openssl/md5.h>
#include <string>

std::string md5(const std::string& input) {
    unsigned char result[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input.c_str(), input.length(), result);

    std::string hash;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", result[i]);
        hash += buf;
    }

    return hash;
}

int main() {
    std::string input = "Hello, world!";
    std::string hash = md5(input);
    std::cout << "MD5 hash of '" << input << "': " << hash << std::endl;
    return 0;
}
