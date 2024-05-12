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
    int min = 10000;
    int max = 100000;
    do {
        num = rand() % (max - min + 1) + min;
    } while (!is_prime(num));

    return num;
}


// (a^b mod n)
uint64_t modExp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1; // same as exponent = exponent / 2
        base = (base * base) % modulus;
    }
    return result;
}

uint64_t modInv(uint64_t a, uint64_t m) {
    uint64_t m0 = m;
    uint64_t y = 0, x = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        uint64_t q = a / m;
        uint64_t t = m;

        m = a % m, a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0)
        x += m0;

    return x;
}

// Encrypts and saves to file, also call generation of key that also saves into a file
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

    uint64_t n;
    fscanf(rsa_pk, "%lld", &n);
    fclose(rsa_pk);

    // Encrypt the message using public key <n,e>
    char message[1000];
    while (fgets(message, sizeof(message), input_fp) != NULL) {
        int len = strlen(message);
        for (int i = 0; i < len; i++) {
            uint64_t encrypted_message;
            if (message[i] == '\n') {
                encrypted_message = '\n'; // We need to know where are the 'enters'
            } else if (!isspace(message[i])) { // only if the character !space
                encrypted_message = modExp(message[i], e, n);
            } else {
                // If  space, set to 0
                encrypted_message = 0;
            }

            FILE *output_fp;
            output_fp = fopen(output_file, "a");
            if (output_fp == NULL) {
                printf("Error: Unable to open %s for writing.\n", output_file);
                return;
            }
            fprintf(output_fp, "%lld ", encrypted_message);
            fclose(output_fp);
        }
    }
}

// Decrypts and save output into a file
void rsa_decrypt(FILE *input_fp, const char *output_file) {
    FILE *rsa_pk = fopen("rsa_key.txt", "r");
    if (rsa_pk == NULL) {
        printf("Error: Unable to open rsa_key.txt.\n");
        return;
    }

    uint64_t n, d;
    fscanf(rsa_pk, "%lld %lld", &n, &d);
    fclose(rsa_pk);

    FILE *output_fp = fopen(output_file, "a");
    if (output_fp == NULL) {
        printf("Error: Unable to open %s for writing.\n", output_file);
        return; // Error handling
    }

    // Decrypts using the private key <n,d>
    uint64_t ciphertext_num;
    while (fscanf(input_fp, "%lld", &ciphertext_num) != EOF) {
        if (ciphertext_num == 0) {
            fprintf(output_fp, " "); // If space, write a space to the output file
        } else if (ciphertext_num == '\n') {
            fprintf(output_fp, "\n"); // Restore newline characters
        } else {
            uint64_t decrypted_message = modExp(ciphertext_num, d, n);
            fprintf(output_fp, "%c", (char)decrypted_message);
        }
    }

    fclose(output_fp);
}

void gen_rsa_pk(const char *filename) {
    srand(time(NULL));

    int p = generate_random_prime();

    // Making sure it's different from p
    int q;
    do {
        q = generate_random_prime();
    } while (q == p);

    // WARNING: says its unreachable but it actually goes trough dont worry :)

    uint64_t n = (uint64_t)p * q;

    // phi or r doenst matter
    uint64_t r = (p - 1) * (q - 1);

    uint64_t d = modInv(e, r);

    // Write n and d to rsa_key.txt
    FILE *fp;
    fp = fopen(filename, "w");
    if (fp == NULL) {
        printf("Error: Unable to open %s for writing.\n", filename);
        return;
    }

    fprintf(fp, "%lld\n", n);
    fprintf(fp, "%lld\n", d);
    fclose(fp);
}