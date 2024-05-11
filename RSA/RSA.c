//
// Created by Praça on 05/05/2024.
//

#include "RSA.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

bool is_prime(int num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;

    for (int i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) return false;
    }

    return true;
}

int generate_random_prime() {
    int num;
    int min = 1000;
    int max = 10000;
    do {
        num = rand() % (max - min + 1) + min;
    } while (!is_prime(num));

    return num;
}


// Function to calculate the modular exponentiation (a^b mod n)
long long int modExp(long long int base, long long int exponent, long long int modulus) {
    long long int result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1; // equivalent to exponent = exponent / 2
        base = (base * base) % modulus;
    }
    return result;
}

// Function to calculate the modular multiplicative inverse of a modulo m
long long int modInv(long long int a, long long int m) {
    long long int m0 = m;
    long long int y = 0, x = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        long long int q = a / m;
        long long int t = m;

        m = a % m, a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0)
        x += m0;

    return x;
}

// Function to rsa_encrypt a message
void rsa_encrypt(FILE *input_fp, const char *output_file) {
    // Generate RSA public key and store it in rsa_key.txt
     gen_rsa_pk("rsa_key.txt");

    // Read n
    FILE *rsa_pk;
    rsa_pk = fopen("rsa_key.txt", "r");
    if (rsa_pk == NULL) {
        printf("Error: Unable to open rsa_key.txt.\n");
        return; // Error handling
    }

    long long int n;
    fscanf(rsa_pk, "%lld", &n);
    fclose(rsa_pk);

    // Encrypt the message from the input file using n and e
    char message[1000];
    while (fgets(message, sizeof(message), input_fp) != NULL) {
        int len = strlen(message);
        for (int i = 0; i < len; i++) {
            long long int encrypted_message;
            if (message[i] == '\n') {
                encrypted_message = '\n'; // Preserve newline characters
            } else if (!isspace(message[i])) { // Encrypt only if the character is not a space
                encrypted_message = modExp(message[i], e, n);
            } else {
                // If the character is a space, set encrypted_message to 0
                encrypted_message = 0;
            }
            // Write the encrypted message to the output file
            FILE *output_fp;
            output_fp = fopen(output_file, "a"); // Use "a" to append instead of overwriting
            if (output_fp == NULL) {
                printf("Error: Unable to open %s for writing.\n", output_file);
                return; // Error handling
            }
            fprintf(output_fp, "%lld ", encrypted_message);
            fclose(output_fp);
        }
    }
}

// Function to rsa_decrypt a ciphertext
void rsa_decrypt(FILE *input_fp, const char *output_file) {
    FILE *rsa_pk = fopen("rsa_key.txt", "r");
    if (rsa_pk == NULL) {
        printf("Error: Unable to open rsa_key.txt.\n");
        return; // Error handling
    }

    long long int n, d;
    fscanf(rsa_pk, "%lld %lld", &n, &d);
    fclose(rsa_pk);

    FILE *output_fp = fopen(output_file, "a");
    if (output_fp == NULL) {
        printf("Error: Unable to open %s for writing.\n", output_file);
        return; // Error handling
    }

    long long int ciphertext_num;
    while (fscanf(input_fp, "%lld", &ciphertext_num) != EOF) {
        if (ciphertext_num == 0) {
            fprintf(output_fp, " "); // If the token represents a space, write a space to the output file
        } else if (ciphertext_num == '\n') {
            fprintf(output_fp, "\n"); // Restore newline characters
        } else {
            long long int decrypted_message = modExp(ciphertext_num, d, n);
            fprintf(output_fp, "%c", (char)decrypted_message);
        }
    }

    fclose(output_fp);
}

void gen_rsa_pk(const char *filename) {
    srand(time(NULL));

    // Generate random prime number p
    int p = generate_random_prime();

    // Generate random prime number q, making sure it's different from p
    int q;
    do {
        q = generate_random_prime();
    } while (q == p);


    // Calculate modulus n
    long long int n = (long long int)p * q;

    // Calculate Euler's totient function r
    long long int r = (p - 1) * (q - 1);

    long long int d = modInv(e, r);

    // Write n and d to rsa_key.txt
    FILE *fp;
    fp = fopen(filename, "w");
    if (fp == NULL) {
        printf("Error: Unable to open %s for writing.\n", filename);
        return; // Error handling
    }

    fprintf(fp, "%lld\n", n);
    fprintf(fp, "%lld\n", d);
    fclose(fp);
}