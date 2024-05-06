//
// Created by Praça on 05/05/2024.
//

#ifndef CRYPTOGRAPHYPROJECT_RSA_H
#define CRYPTOGRAPHYPROJECT_RSA_H

#include <stdio.h>
#include <math.h>

#define p   (11) // large prime
#define q   (3) // another large prime

// public key n
#define n (p*q)

#define r ((p - 1)*(q - 1))

#define e   (3) // can be either 3,5,17 & 65537 the bigger the number the more secure it is
#define d   (7)

// Function to calculate a^b mod n  (a-> base, b-> exponent)
int modExp(int base, int exponent, int modulus);
int encrypt(int message);
int decrypt(int ciphertext);

#endif //CRYPTOGRAPHYPROJECT_RSA_H
