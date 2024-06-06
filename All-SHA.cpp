#include <iostream>
#include <openssl/sha.h>
#include <string>

std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input.c_str(), input.length(), hash);

    std::string hashStr;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hashStr += buf;
    }

    return hashStr;
}

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

std::string sha384(const std::string& input) {
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, input.c_str(), input.length());
    SHA384_Final(hash, &sha384);

    std::string hashStr;
    for (int i = 0; i < SHA384_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hashStr += buf;
    }

    return hashStr;
}

std::string sha512(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, input.c_str(), input.length());
    SHA512_Final(hash, &sha512);

    std::string hashStr;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hashStr += buf;
    }

    return hashStr;
}

int main() {
    std::string input = "Hello, world!";
    std::cout << "SHA-1 hash of '" << input << "': " << sha1(input) << std::endl;
    std::cout << "SHA-256 hash of '" << input << "': " << sha256(input) << std::endl;
    std::cout << "SHA-384 hash of '" << input << "': " << sha384(input) << std::endl;
    std::cout << "SHA-512 hash of '" << input << "': " << sha512(input) << std::endl;
    return 0;
}
