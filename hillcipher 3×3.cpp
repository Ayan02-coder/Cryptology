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
            if ((a * x) % m == 0) {
                return x;
            }
        }
        return -1;
    }

    int determinant(const vector<vector<int>>& matrix) {
        int det = 0;
        if (matrix.size() == 2) {
            det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26;
        } else {
            for (int i = 0; i < matrix.size(); ++i) {
                vector<vector<int>> subMatrix(matrix.size() - 1, vector<int>(matrix.size() - 1));
                for (int row = 1; row < matrix.size(); ++row) {
                    int colIndex = 0;
                    for (int col = 0; col < matrix.size(); ++col) {
                        if (col == i) continue;
                        subMatrix[row - 1][colIndex++] = matrix[row][col];
                    }
                }
                det += (i % 2 == 0 ? 1 : -1) * matrix[0][i] * determinant(subMatrix);
                det %= 26;
            }
        }
        return (det + 26) % 26;
    }

    vector<vector<int>> adjugateMatrix(const vector<vector<int>>& matrix) {
        int n = matrix.size();
        vector<vector<int>> adjMatrix(n, vector<int>(n));
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                vector<vector<int>> subMatrix(n - 1, vector<int>(n - 1));
                for (int row = 0; row < n; ++row) {
                    for (int col = 0; col < n; ++col) {
                        if (row != i && col != j) {
                            subMatrix[row < i ? row : row - 1][col < j ? col : col - 1] = matrix[row][col];
                        }
                    }
                }
                int cofactor = determinant(subMatrix);
                if ((i + j) % 2 == 1) cofactor = -cofactor;
                adjMatrix[j][i] = (cofactor + 26) % 26;
            }
        }
        return adjMatrix;
    }

    vector<vector<int>> calculateInverseMatrix(const vector<vector<int>>& matrix) {
        int det = determinant(matrix);
        int invDet = modInverse(det, 26);
        vector<vector<int>> adjMatrix = adjugateMatrix(matrix);
        vector<vector<int>> invMatrix(matrix.size(), vector<int>(matrix.size()));
        for (int i = 0; i < matrix.size(); ++i) {
            for (int j = 0; j < matrix.size(); ++j) {
                invMatrix[i][j] = (adjMatrix[i][j] * invDet) % 26;
                if (invMatrix[i][j] < 0) invMatrix[i][j] += 26;
            }
        }
        return invMatrix;
    }
};

int main() {
    vector<vector<int>> keyMatrix = {
        {6, 24, 1},
        {13, 16, 10},
        {20, 17, 15}
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
