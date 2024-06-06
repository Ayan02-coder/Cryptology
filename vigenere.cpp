#include <iostream>
#include <string>
using namespace std;

class VigenereCipher {
public:
    string encode(const string& plaintext, const string& key) {
        string extendedKey = extendKey(plaintext, key);
        string ciphertext = plaintext;
        for (size_t i = 0; i < plaintext.size(); ++i) {
            ciphertext[i] = ((plaintext[i] - 'A') + (extendedKey[i] - 'A')) % 26 + 'A';
        }
        return ciphertext;
    }

    string decode(const string& ciphertext, const string& key) {
        string extendedKey = extendKey(ciphertext, key);
        string plaintext = ciphertext;
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            plaintext[i] = ((ciphertext[i] - 'A') - (extendedKey[i] - 'A') + 26) % 26 + 'A';
        }
        return plaintext;
    }

private:
    string extendKey(const string& text, const string& key) {
        string extendedKey;
        for (size_t i = 0; i < text.size(); ++i) {
            extendedKey += key[i % key.size()];
        }
        return extendedKey;
    }
};

int main() {
    string plaintext, key;
    cout << "Enter plaintext (uppercase letters only): ";
    getline(cin, plaintext);

    cout << "Enter key (uppercase letters only): ";
    getline(cin, key);

    // Ensure inputs are uppercase letters
    for (char &c : plaintext) c = toupper(c);
    for (char &c : key) c = toupper(c);

    VigenereCipher cipher;

    string ciphertext = cipher.encode(plaintext, key);
    cout << "Encoded text: " << ciphertext << endl;

    string decodedText = cipher.decode(ciphertext, key);
    cout << "Decoded text: " << decodedText << endl;

    return 0;
}
