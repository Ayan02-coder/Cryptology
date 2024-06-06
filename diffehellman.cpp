#include <iostream>
#include <cmath>
using namespace std;

// Function to calculate (base^exponent) % modulus efficiently
long long powerMod(long long base, long long exponent, long long modulus) {
    long long result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

// Function to perform Diffie-Hellman key exchange
void diffieHellman(long long base, long long modulus) {
    long long privateKeyA, privateKeyB;
    cout << "Enter private key for user A: ";
    cin >> privateKeyA;
    cout << "Enter private key for user B: ";
    cin >> privateKeyB;

    // Calculate public keys for both users
    long long publicKeyA = powerMod(base, privateKeyA, modulus);
    long long publicKeyB = powerMod(base, privateKeyB, modulus);

    // Calculate shared secret for both users
    long long sharedSecretA = powerMod(publicKeyB, privateKeyA, modulus);
    long long sharedSecretB = powerMod(publicKeyA, privateKeyB, modulus);

    cout << "User A's public key: " << publicKeyA << endl;
    cout << "User B's public key: " << publicKeyB << endl;
    cout << "User A's shared secret: " << sharedSecretA << endl;
    cout << "User B's shared secret: " << sharedSecretB << endl;
}

int main() {
    long long base, modulus;
    cout << "Enter the base value: ";
    cin >> base;
    cout << "Enter the modulus value: ";
    cin >> modulus;

    diffieHellman(base, modulus);

    return 0;
}
