#include <iostream>
#include <cmath>

using namespace std;

// Power function to return value of a ^ b mod P
long long int power(long long int a, long long int b, long long int P) {
    if (b == 1)
        return a;
    else
        return (((long long int)pow(a, b)) % P);
}

int main() {
    long long int P, G, a, b;

    // Getting input from the user
    cout << "Enter the value of P (prime number): ";
    cin >> P;

    cout << "Enter the value of G (primitive root for P): ";
    cin >> G;

    cout << "Enter the private key for Alice (a): ";
    cin >> a;

    cout << "Enter the private key for Bob (b): ";
    cin >> b;

    cout << "The value of P : " << P << endl;
    cout << "The value of G : " << G << endl;
    cout << "The private key a for Alice : " << a << endl;
    cout << "The private key b for Bob : " << b << endl;

    // Calculating the public keys
    long long int x = power(G, a, P); // Key for Alice
    long long int y = power(G, b, P); // Key for Bob

    // Generating the secret key after the exchange
    long long int ka = power(y, a, P); // Secret key for Alice
    long long int kb = power(x, b, P); // Secret key for Bob

    cout << "Secret key for Alice is: " << ka << endl;
    cout << "Secret key for Bob is: " << kb << endl;

    return 0;
}
