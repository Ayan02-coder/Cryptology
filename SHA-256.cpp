#include <iostream>
#include <openssl/sha.h>
#include <string>

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    std::string hashStr;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hashStr += buf;
    }

    return hashStr;
}

int main() {
    std::string input = "Hello, world!";
    std::string hash = sha256(input);
    std::cout << "SHA-256 hash of '" << input << "': " << hash << std::endl;
    return 0;
}
