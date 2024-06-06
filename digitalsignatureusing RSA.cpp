#include <iostream>
#include <cmath>

using namespace std;

// Function to calculate GCD of two numbers
int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Function to generate keys
void generateKeys(int p, int q, int &n, int &e, int &d) {
    n = p * q;
    int phi = (p - 1) * (q - 1);

    // Choose e such that 1 < e < phi and gcd(e, phi) = 1
    for (e = 2; e < phi; e++) {
        if (gcd(e, phi) == 1)
            break;
    }

    // Calculate d such that (d * e) % phi = 1
    for (d = 2; d < phi; d++) {
        if ((d * e) % phi == 1)
            break;
    }
}

// Function to encrypt a message
int encrypt(int msg, int e, int n) {
    return (int)pow(msg, e) % n;
}

// Function to decrypt a message
int decrypt(int encryptedMsg, int d, int n) {
    return (int)pow(encryptedMsg, d) % n;
}

int main() {
    // Prime numbers for generating keys
    int p = 61;
    int q = 53;
    
    int n, e, d;
    generateKeys(p, q, n, e, d);

    // Get user input for the message to be signed
    int msg;
    cout << "Enter the message to be signed: ";
    cin >> msg;

    // Encrypt the message
    int encryptedMsg = encrypt(msg, e, n);
    cout << "Encrypted Message: " << encryptedMsg << endl;

    // Decrypt the message
    int decryptedMsg = decrypt(encryptedMsg, d, n);
    cout << "Decrypted Message: " << decryptedMsg << endl;

    // Verification
    if (msg == decryptedMsg) {
        cout << "Signature verified." << endl;
    } else {
        cout << "Signature not verified." << endl;
    }

    return 0;
}
