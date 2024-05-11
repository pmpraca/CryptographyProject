//
// Created by Praça on 05/05/2024.
//

#ifndef CRYPTOGRAPHYPROJECT_RSA_H
#define CRYPTOGRAPHYPROJECT_RSA_H

#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>

#define e (65537) // can be either 3, 5, 17, or 65537; the bigger the number the more secure it is


// Function prototypes
int generate_random_prime();
long long int modExp(long long int base, long long int exponent, long long int modulus);
long long int modInv(long long int a, long long int m);
void rsa_encrypt(FILE *input_fp, const char *output_file);
void rsa_decrypt(FILE *input_fp, const char *output_file);
void gen_rsa_pk(const char *filename);

#endif //CRYPTOGRAPHYPROJECT_RSA_H
