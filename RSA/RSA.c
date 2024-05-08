//
// Created by Praça on 05/05/2024.
//

#include "RSA.h"

// Function to calculate the modular exponentiation (a^b mod n)
int modExp(int base, int exponent, int modulus) {
    printf("Base: %d\n" ,base);
    printf("Exponent: %d\n" ,exponent);
    printf("Modulus: %d\n" ,modulus);

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
    int m0 = m;
    int y = 0, x = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        // q is quotient
        int Q = a / m;
        int t = m;

        // m is remainder now, process same as Euclid's algo
        m = a % m, a = t;
        t = y;

        // Update y and x
        y = x - Q * y;
        x = t;
    }

    // Make x positive
    if (x < 0)
        x += m0;

    return x;
}

// Function to encrypt a message
int encrypt(int message) {
    return modExp(message, e, n); // send the pubKey(e,n)
}

// Function to decrypt a message
int decrypt(int ciphertext) {
    int d = modInv(e, r); // Calculate private exponent d
    printf("R= %d", r);
    printf("D= %d\n", d);
    return modExp(ciphertext, d, n); // prKey(d)
}
