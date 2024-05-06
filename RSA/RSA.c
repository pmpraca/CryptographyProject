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

int modInv(int a, int m) {
    int m0 = m, t, Q; // Q -> quocient
    int x0 = 0, x1 = 1;

    if (m == 1)
        return 0;

    // Apply extended Euclid Algorithm
    while (a > 1) {

        Q = a / m;

        t = m;

        // m is remainder now, process same as Euclid's algo
        m = a % m, a = t;

        t = x0;

        x0 = x1 - Q * x0;

        x1 = t;
    }

    // Make x1 positive
    if (x1 < 0)
        x1 += m0;

    return x1;
}

// Function to encrypt a message
int encrypt(int message) {
    return modExp(message, e, n); // send the pubKey(e,n)
}

/*
// Function to decrypt a message
int decrypt(int ciphertext) {
    return modExp(ciphertext, d, n); // prKey(d)
}*/

// Function to decrypt a message
int decrypt(int ciphertext) {
    int d = modInv(e, r); // Calculate private exponent d
    return modExp(ciphertext, d, n); // prKey(d)
}
