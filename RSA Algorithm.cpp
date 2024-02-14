#include <iostream>
#include <cmath>
using namespace std;

int gcd(int a, int b) {
   int t;
   while(1) {
      t = a % b;
      if (t == 0)
         return b;
      a = b;
      b = t;
   }
}

int main() {
   double p, q, e, message;
   cout << "Enter the value of p: ";
   cin >> p;
   cout << "Enter the value of q: ";
   cin >> q;
   double n = p * q;
   double track;
   double phi = (p - 1) * (q - 1);
   cout << "Enter the value of e (such that 1 < e < " << phi << " and gcd(e, phi) = 1): ";
   cin >> e;

   while (e >= phi || gcd(e, phi) != 1) {
      cout << "Invalid value of e! Enter a value such that 1 < e < " << phi << " and gcd(e, phi) = 1: ";
      cin >> e;
   }

   cout << "Enter the message to encrypt: ";
   cin >> message;

   double d1 = 1 / e;
   double d = fmod(d1, phi);
   double c = pow(message, e);
   double m = pow(c, d);
   c = fmod(c, n);
   m = fmod(m, n);
   cout << "Original Message = " << message << endl;
   cout << "p = " << p << endl;
   cout << "q = " << q << endl;
   cout << "n = pq = " << n << endl;
   cout << "phi = " << phi << endl;
   cout << "e = " << e << endl;
   cout << "d = " << d << endl;
   cout << "Encrypted message = " << c << endl;
   cout << "Decrypted message = " << m << endl;
   return 0;
}
    