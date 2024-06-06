#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>

using namespace std;

class VernamCipher {
public:
    string generateKey(int length) {
        string key;
        for (int i = 0; i < length; ++i) {
            key += (rand() % 26) + 'A';
        }
        return key;
    }

    string encode(const string& plaintext, const string& key) {
        string ciphertext = plaintext;
        for (size_t i = 0; i < plaintext.size(); ++i) {
            ciphertext[i] = ((plaintext[i] - 'A') + (key[i] - 'A')) % 26 + 'A';
        }
        return ciphertext;
    }

    string decode(const string& ciphertext, const string& key) {
        string plaintext = ciphertext;
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            plaintext[i] = ((ciphertext[i] - 'A') - (key[i] - 'A') + 26) % 26 + 'A';
        }
        return plaintext;
    }
};

int main() {
    srand(time(0)); // Seed the random number generator

    string plaintext;
    cout << "Enter plaintext (uppercase letters only): ";
    getline(cin, plaintext);

    VernamCipher cipher;
    string key = cipher.generateKey(plaintext.size());
    cout << "Generated key: " << key << endl;

    string ciphertext = cipher.encode(plaintext, key);
    cout << "Encoded text: " << ciphertext << endl;

    string decodedText = cipher.decode(ciphertext, key);
    cout << "Decoded text: " << decodedText << endl;

    return 0;
}
