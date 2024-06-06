#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
using namespace std;

// Function to encrypt the plaintext using columnar transposition cipher
string encrypt(const string& plaintext, const string& key) {
    string ciphertext;
    int keyLength = key.length();
    int textLength = plaintext.length();
    
    // Calculate the number of rows required
    int numRows = (textLength + keyLength - 1) / keyLength;
    
    // Create a matrix to store the plaintext characters
    vector<vector<char>> matrix(numRows, vector<char>(keyLength));
    
    // Fill the matrix with the plaintext characters
    int index = 0;
    for (int i = 0; i < numRows; ++i) {
        for (int j = 0; j < keyLength; ++j) {
            if (index < textLength) {
                matrix[i][j] = plaintext[index++];
            } else {
                matrix[i][j] = ' ';
            }
        }
    }
    
    // Arrange columns according to the key
    for (char ch : key) {
        int colIndex = ch - '0' - 1;
        for (int i = 0; i < numRows; ++i) {
            ciphertext += matrix[i][colIndex];
        }
    }
    
    return ciphertext;
}
// Function to decrypt the ciphertext using columnar transposition cipher
string decrypt(const string& ciphertext, const string& key) {
    string plaintext;
    int keyLength = key.length();
    int textLength = ciphertext.length();
    
    // Calculate the number of rows required
    int numRows = (textLength + keyLength - 1) / keyLength;
    
    // Create a matrix to store the ciphertext characters
    vector<vector<char>> matrix(numRows, vector<char>(keyLength));
    
    // Calculate the number of characters in the last row
    int lastRowLength = textLength % keyLength;
    if (lastRowLength == 0) {
        lastRowLength = keyLength;
    }
    
    // Calculate the number of characters in the other rows
    int otherRowLength = keyLength - lastRowLength;
    
    // Calculate the number of complete rows
    int completeRows = numRows - 1;
    
    // Calculate the number of columns in the last row
    int lastRowCols = (completeRows * otherRowLength) + lastRowLength;
    
    // Calculate the number of columns in the other rows
    int otherRowCols = (completeRows * otherRowLength);
    
    // Calculate the index of the first character of the last row
    int lastIndex = (numRows - 1) * keyLength;
    
    // Arrange columns according to the key
    int colIndex = 0;
    for (char ch : key) {
        int keyDigit = ch - '0' - 1;
        int numCols = (colIndex < lastRowCols) ? numRows : (numRows - 1);
        
        // Read characters from ciphertext into the matrix column by column
        for (int i = 0; i < numCols; ++i) {
            matrix[i][keyDigit] = ciphertext[colIndex++];
        }
    }
    
    // Read the plaintext from the matrix row by row
    for (int i = 0; i < numRows; ++i) {
        for (int j = 0; j < keyLength; ++j) {
            plaintext += matrix[i][j];
        }
    }
    
    return plaintext;
}
int main() {
    string plaintext, key, ciphertext;
    
    // Prompt user for plaintext and key
    cout << "Enter plaintext: ";
    getline(cin, plaintext);
    cout << "Enter key (digits only, e.g., 3124): ";
    getline(cin, key);
    
    // Encrypt the plaintext using columnar transposition cipher
    ciphertext = encrypt(plaintext, key);
    cout << "Encrypted text: " << ciphertext << endl;
    
    // Decrypt the ciphertext using columnar transposition cipher
    string decryptedText = decrypt(ciphertext, key);
    cout << "Decrypted text: " << decryptedText << endl;
    
    return 0;
}
