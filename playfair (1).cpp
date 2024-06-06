#include <iostream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <map>
using namespace std;

class PlayfairCipher {
public:
    PlayfairCipher(string key) {
        generateKeyMatrix(key);
    }

    string encode(string plaintext) {
        prepareText(plaintext);
        return processText(plaintext, true);
    }

    string decode(string ciphertext) {
        return processText(ciphertext, false);
    }

private:
    vector<vector<char>> keyMatrix;
    map<char, pair<int, int>> charPos;

    void generateKeyMatrix(string key) {
        // Remove duplicates from key and convert to uppercase
        string processedKey = "";
        bool alphabetUsed[26] = { false };

        for (char ch : key) {
            ch = toupper(ch);
            if (ch == 'J') ch = 'I'; // Treat 'J' as 'I'
            if (!alphabetUsed[ch - 'A'] && isalpha(ch)) {
                processedKey += ch;
                alphabetUsed[ch - 'A'] = true;
            }
        }

        // Add remaining letters of the alphabet
        for (char ch = 'A'; ch <= 'Z'; ++ch) {
            if (ch == 'J') continue;
            if (!alphabetUsed[ch - 'A']) {
                processedKey += ch;
                alphabetUsed[ch - 'A'] = true;
            }
        }

        // Fill key matrix
        keyMatrix.resize(5, vector<char>(5));
        int index = 0;
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < 5; ++j) {
                keyMatrix[i][j] = processedKey[index];
                charPos[processedKey[index]] = {i, j};
                ++index;
            }
        }
    }

    void prepareText(string &text) {
        transform(text.begin(), text.end(), text.begin(), ::toupper);
        text.erase(remove_if(text.begin(), text.end(), [](char c) { return !isalpha(c); }), text.end());
        for (size_t i = 0; i < text.length(); i += 2) {
            if (i + 1 == text.length()) {
                text += 'X';
            }
            if (text[i] == text[i + 1]) {
                text.insert(i + 1, 1, 'X');
            }
        }
    }

    string processText(string text, bool encode) {
        string result = "";
        int direction = encode ? 1 : -1;

        for (size_t i = 0; i < text.length(); i += 2) {
            char a = text[i];
            char b = text[i + 1];
            auto [row1, col1] = charPos[a];
            auto [row2, col2] = charPos[b];

            if (row1 == row2) {
                result += keyMatrix[row1][(col1 + direction + 5) % 5];
                result += keyMatrix[row2][(col2 + direction + 5) % 5];
            } else if (col1 == col2) {
                result += keyMatrix[(row1 + direction + 5) % 5][col1];
                result += keyMatrix[(row2 + direction + 5) % 5][col2];
            } else {
                result += keyMatrix[row1][col2];
                result += keyMatrix[row2][col1];
            }
        }

        return result;
    }
};

int main() {
    string key, plaintext, ciphertext;
    cout << "Enter key: ";
    getline(cin, key);

    PlayfairCipher cipher(key);

    cout << "Enter plaintext: ";
    getline(cin, plaintext);

    ciphertext = cipher.encode(plaintext);
    cout << "Encoded text: " << ciphertext << endl;

    string decodedText = cipher.decode(ciphertext);
    cout << "Decoded text: " << decodedText << endl;

    return 0;
}
