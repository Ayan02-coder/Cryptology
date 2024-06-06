#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;

string rijndaelEncrypt(string plaintext, byte key[], byte iv[]) {
    string ciphertext;

    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryption,
                new StringSink(ciphertext)
            )
        );
    }
    catch(const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    return ciphertext;
}

string rijndaelDecrypt(string ciphertext, byte key[], byte iv[]) {
    string decryptedText;

    try {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryption,
                new StringSink(decryptedText)
            )
        );
    }
    catch(const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    return decryptedText;
}

int main() {
    byte key[AES::DEFAULT_KEYLENGTH] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
    byte iv[AES::BLOCKSIZE] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
    
    string plaintext = "Hello, AES!";
    string encrypted = rijndaelEncrypt(plaintext, key, iv);

    cout << "Encrypted: " << encrypted << endl;

    string decrypted = rijndaelDecrypt(encrypted, key, iv);

    cout << "Decrypted: " << decrypted << endl;

    return 0;
}
