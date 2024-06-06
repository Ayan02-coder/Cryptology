#include <iostream>
#include <vector>
#include <string>
using namespace std;

class HillCipher {
public:
    HillCipher(const vector<vector<int>>& keyMatrix) {
        this->keyMatrix = keyMatrix;
        matrixSize = keyMatrix.size();
        inverseKeyMatrix = calculateInverseMatrix(keyMatrix);
    }

    string encode(const string& plaintext) {
        vector<int> numericText = convertToNumbers(plaintext);
        while (numericText.size() % matrixSize != 0) {
            numericText.push_back(0); // Padding with 'A'
        }
        vector<int> encodedText = multiplyMatrix(numericText, keyMatrix);
        return convertToString(encodedText);
    }

    string decode(const string& ciphertext) {
        vector<int> numericText = convertToNumbers(ciphertext);
        vector<int> decodedText = multiplyMatrix(numericText, inverseKeyMatrix);
        return convertToString(decodedText);
    }

private:
    vector<vector<int>> keyMatrix;
    vector<vector<int>> inverseKeyMatrix;
    int matrixSize;

    vector<int> convertToNumbers(const string& text) {
        vector<int> numbers;
        for (char ch : text) {
            if (isalpha(ch)) {
                numbers.push_back(toupper(ch) - 'A');
            }
        }
        return numbers;
    }

    string convertToString(const vector<int>& numbers) {
        string text;
        for (int num : numbers) {
            text += (num % 26) + 'A';
        }
        return text;
    }

    vector<int> multiplyMatrix(const vector<int>& text, const vector<vector<int>>& matrix) {
        vector<int> result(text.size());
        for (size_t i = 0; i < text.size(); i += matrixSize) {
            for (int j = 0; j < matrixSize; ++j) {
                int sum = 0;
                for (int k = 0; k < matrixSize; ++k) {
                    sum += matrix[j][k] * text[i + k];
                }
                result[i + j] = sum % 26;
            }
        }
        return result;
    }

    int modInverse(int a, int m) {
        a = a % m;
        for (int x = 1; x < m; ++x) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        return -1;
    }

    int determinant(const vector<vector<int>>& matrix) {
        // For 2x2 matrix: det = a*d - b*c
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26;
    }

    vector<vector<int>> calculateInverseMatrix(const vector<vector<int>>& matrix) {
        int det = determinant(matrix);
        int invDet = modInverse(det, 26);
        vector<vector<int>> invMatrix(matrixSize, vector<int>(matrixSize));

        invMatrix[0][0] = matrix[1][1] * invDet % 26;
        invMatrix[0][1] = -matrix[0][1] * invDet % 26;
        invMatrix[1][0] = -matrix[1][0] * invDet % 26;
        invMatrix[1][1] = matrix[0][0] * invDet % 26;

        for (int i = 0; i < matrixSize; ++i) {
            for (int j = 0; j < matrixSize; ++j) {
                if (invMatrix[i][j] < 0) invMatrix[i][j] += 26;
            }
        }

        return invMatrix;
    }
};

int main() {
    vector<vector<int>> keyMatrix = {
        {3, 3},
        {2, 5}
    };

    HillCipher cipher(keyMatrix);

    string plaintext, ciphertext;
    cout << "Enter plaintext: ";
    getline(cin, plaintext);

    ciphertext = cipher.encode(plaintext);
    cout << "Encoded text: " << ciphertext << endl;

    string decodedText = cipher.decode(ciphertext);
    cout << "Decoded text: " << decodedText << endl;

    return 0;
}
