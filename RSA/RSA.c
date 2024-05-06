//
// Created by Praça on 05/05/2024.
//

#include "RSA.h"

// Function to calculate the modular exponentiation (a^b mod n)
int modExp(int base, int exponent, int modulus) {
    int result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1; // equivalent to exponent = exponent / 2
        base = (base * base) % modulus;
    }
    return result;
}

// Function to encrypt a message
int encrypt(int message) {
    return modExp(message, e, n); // send the pubKey(e,n)
}

// Function to decrypt a message
int decrypt(int ciphertext) {
    return modExp(ciphertext, d, n); // prKey(d)
}
