#include <iostream>
#include <string>
using namespace std;

class VernamCipher {
public:
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
    string plaintext, key;
    cout << "Enter plaintext (uppercase letters only): ";
    getline(cin, plaintext);

    cout << "Enter key (uppercase letters only, same length as plaintext): ";
    getline(cin, key);

    // Ensure the key is the same length as the plaintext
    if (key.length() != plaintext.length()) {
        cout << "Error: Key must be the same length as the plaintext." << endl;
        return 1;
    }

    VernamCipher cipher;

    string ciphertext = cipher.encode(plaintext, key);
    cout << "Encoded text: " << ciphertext << endl;

    string decodedText = cipher.decode(ciphertext, key);
    cout << "Decoded text: " << decodedText << endl;

    return 0;
}
