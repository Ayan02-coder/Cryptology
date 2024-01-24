#include<iostream>
#include<string>
#include<vector>
#include<map>

using namespace std;

class PlayfairCipher {
private:
    string key;
    vector<vector<char>> matrix;

    void prepareKeyMatrix() {
        // Create a matrix based on the given key
        map<char, bool> used;
        int row = 0, col = 0;

        for (char c : key) {
            if (!used[c] && c != 'j') {
                matrix[row][col] = c;
                used[c] = true;
                col++;
                if (col == 5) {
                    col = 0;
                    row++;
                }
            }
        }

        for (char c = 'a'; c <= 'z'; c++) {
            if (!used[c] && c != 'j') {
                matrix[row][col] = c;
                col++;
                if (col == 5) {
                    col = 0;
                    row++;
                }
            }
        }
    }

    pair<int, int> findPosition(char letter) {
        // Find the position of a letter in the matrix
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                if (matrix[i][j] == letter) {
                    return make_pair(i, j);
                }
            }
        }
        return make_pair(-1, -1); // Not found
    }

public:
    PlayfairCipher(const string& key) : key(key) {
        matrix.resize(5, vector<char>(5, ' '));
        prepareKeyMatrix();
    }

    string encrypt(const string& plaintext) {
        string ciphertext;
        for (int i = 0; i < plaintext.size(); i += 2) {
            char first = plaintext[i];
            char second = (i + 1 < plaintext.size()) ? plaintext[i + 1] : 'x';

            pair<int, int> pos1 = findPosition(first);
            pair<int, int> pos2 = findPosition(second);

            if (pos1.first == pos2.first) {
                // Same row
                ciphertext += matrix[pos1.first][(pos1.second + 1) % 5];
                ciphertext += matrix[pos2.first][(pos2.second + 1) % 5];
            } else if (pos1.second == pos2.second) {
                // Same column
                ciphertext += matrix[(pos1.first + 1) % 5][pos1.second];
                ciphertext += matrix[(pos2.first + 1) % 5][pos2.second];
            } else {
                // Different rows and columns
                ciphertext += matrix[pos1.first][pos2.second];
                ciphertext += matrix[pos2.first][pos1.second];
            }
        }
        return ciphertext;
    }

    string decrypt(const string& ciphertext) {
        string plaintext;
        for (int i = 0; i < ciphertext.size(); i += 2) {
            char first = ciphertext[i];
            char second = (i + 1 < ciphertext.size()) ? ciphertext[i + 1] : 'x';

            pair<int, int> pos1 = findPosition(first);
            pair<int, int> pos2 = findPosition(second);

            if (pos1.first == pos2.first) {
                // Same row
                plaintext += matrix[pos1.first][(pos1.second - 1 + 5) % 5];
                plaintext += matrix[pos2.first][(pos2.second - 1 + 5) % 5];
            } else if (pos1.second == pos2.second) {
                // Same column
                plaintext += matrix[(pos1.first - 1 + 5) % 5][pos1.second];
                plaintext += matrix[(pos2.first - 1 + 5) % 5][pos2.second];
            } else {
                // Different rows and columns
                plaintext += matrix[pos1.first][pos2.second];
                plaintext += matrix[pos2.first][pos1.second];
            }
        }
        return plaintext;
    }
};

int main() {
    string key, message;
    
    cout << "Enter the key: ";
    cin >> key;

    cout << "Enter the message: ";
    cin.ignore();  // Clear the newline character from the buffer
    getline(cin, message);

    // Create PlayfairCipher object
    PlayfairCipher playfair(key);

    // Encrypt the message
    string ciphertext = playfair.encrypt(message);
    cout << "Encrypted message: " << ciphertext << endl;

    // Decrypt the message
    string decryptedMessage = playfair.decrypt(ciphertext);
    cout << "Decrypted message: " << decryptedMessage << endl;

    return 0;
}
