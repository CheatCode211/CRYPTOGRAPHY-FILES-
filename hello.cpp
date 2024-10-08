#include <iostream>
#include <string>

using namespace std;

string encryptDecrypt(string toEncrypt) {
    char key = 'K'; // Any char will work
    string output = toEncrypt;
    
    for (int i = 0; i < toEncrypt.size(); i++)
        output[i] = toEncrypt[i] ^ key;
    
    return output;
}

int main() {
    string userInput;
    
    cout << "Enter a string to encrypt: ";
    getline(cin, userInput);
    
    string encrypted = encryptDecrypt(userInput);
    cout << "Encrypted: " << encrypted << "\n";
    
    string decrypted = encryptDecrypt(encrypted);
    cout << "Decrypted: " << decrypted << "\n";
    
    return 0;
}
