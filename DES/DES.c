//
// Created by Praça on 05/05/2024.
//

#include "DES.h"
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define the same constants as in the online implementation
#define LB64_MASK 0x0000000000000001
#define L64_MASK 0x00000000ffffffff
#define LB32_MASK 0x00000001

// Initial permutation
static char IP[] = {
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
};

// Inverse Permutation
static char inverse_IP[] = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
};


// E Bit-Selection table
static char E_bit_selection[] = {
        32,  1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
};

// primitive function of P - Post S-Box permutation
static char P[] = {
        16,  7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
};

// Sbox tables from 1 - 8
static char Sboxes[8][64] = {{
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
        0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
        4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
        },
        {
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
        3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
        0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
        },
        {
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
        1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
        },
        {
        7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
        3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
        },
        {
        2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
        4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
        },
        {
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
        9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
        4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
        },
        {
        4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
        1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
        6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
        },
        {
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
        1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
        7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
        2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }};

// Permuted Choice 1 is determined by the following table:
static char PC_1[] = {
        57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,

        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
};

// Permuted Choice 2 is determined by the following table:
static char PC_2[] = {
        14, 17, 11, 24,  1,  5,
        3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};

// Key bit shifted per round array (1,2,9 & 16 shifted by 1; the others are by 2)
static char iteration_shift[] = { 1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1 };

// Function for initial permutation
uint64_t initial_permutation(uint64_t input) {
    uint64_t init_perm_res = 0;
    for (int i = 0; i < 64; i++) {
        init_perm_res <<= 1;
        init_perm_res |= (input >> (64 - IP[i])) & LB64_MASK;
    }
    return init_perm_res;
}

// Function for inverse initial permutation
uint64_t inverse_initial_permutation(uint64_t pre_output) {
    uint64_t inv_init_perm_res = 0;
    for (int i = 0; i < 64; i++) {
        inv_init_perm_res <<= 1;
        inv_init_perm_res |= (pre_output >> (64 - inverse_IP[i])) & LB64_MASK;
    }
    return inv_init_perm_res;
}

// Function for initial key schedule calculation
void initial_key_schedule(uint64_t key, uint32_t *C, uint32_t *D) {
    uint64_t permuted_choice_1 = 0;
    for (int i = 0; i < 56; i++) {
        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (key >> (64 - PC_1[i])) & LB64_MASK;
    }
    *C = (uint32_t)((permuted_choice_1 >> 28) & 0x000000000fffffff);
    *D = (uint32_t)(permuted_choice_1 & 0x000000000fffffff);
}

// Function for calculation of the 16 keys
void calculate_sub_keys(uint32_t C, uint32_t D, uint64_t *sub_keys) {
    for (int i = 0; i < 16; i++) {
        // Key schedule
        for (int j = 0; j < iteration_shift[i]; j++) {
            C = 0x0fffffff & (C << 1) | 0x00000001 & (C >> 27);
            D = 0x0fffffff & (D << 1) | 0x00000001 & (D >> 27);

        }
        uint64_t permuted_choice_2 = 0;
        permuted_choice_2 = (((uint64_t)C) << 28) | (uint64_t) D;
        sub_keys[i] = 0;
        for (int j = 0; j < 48; j++) {
            sub_keys[i] <<= 1;
            sub_keys[i] |= (permuted_choice_2 >> (56 - PC_2[j])) & LB64_MASK;
        }
    }
}

// Function for function f(R, K) calculation
uint32_t calculate_f(uint32_t R, uint64_t *sub_key, char mode, int iteration_i) {
    uint32_t s_output = 0;
    uint32_t f_function_res = 0;
    uint64_t s_input = 0;

    // Expansion permutation
    for (int j = 0; j < 48; j++) {
        s_input <<= 1;
        s_input |= (uint64_t)((R >> (32 - E_bit_selection[j])) & LB32_MASK);
    }

    if (mode == 'd') {
        // Decryption
        s_input = s_input ^ sub_key[15 - iteration_i];
    } else {
        // Encryption
        s_input = s_input ^ sub_key[iteration_i];
    }

    // S-Box substitution
    for (int j = 0; j < 8; j++) { 
        char row = (char)((s_input & (0x0000840000000000 >> 6 * j)) >> (42-6*j));
        row = (row >> 4) | (row & 0x01);
        char column = (char)((s_input & (0x0000780000000000 >> 6 * j)) >> (43-6*j));
        s_output <<= 4;
        s_output |= (uint32_t)(Sboxes[j][16 * row + column] & 0x0f);
    }
    f_function_res = 0;
    // Permutation
    for (int j = 0; j < 32; j++) {
        f_function_res <<= 1;
        f_function_res |= (s_output >> (32 - P[j])) & LB32_MASK;
    }

    return f_function_res;
}

// Main DES function
uint64_t des(uint64_t input, uint64_t key, char mode) {
    uint32_t C, D = 0;
    uint64_t sub_keys[16];
    uint64_t s_input = 0;
    // Initial permutation
    uint64_t init_perm_res = initial_permutation(input);
    // Initial key schedule calculation
    initial_key_schedule(key, &C, &D);
    // Calculation of the 16 keys
    calculate_sub_keys(C, D, sub_keys);
    // Function f(R, K) calculation

    uint32_t L = (uint32_t)(init_perm_res >> 32) & L64_MASK;
    uint32_t R = (uint32_t)init_perm_res & L64_MASK;

    for (int i = 0; i < 16; i++) {

        s_input = 0;

        uint32_t f_function_res = calculate_f(R, sub_keys, mode, i);
        uint32_t temp = R;
        R = L ^ f_function_res;
        L = temp;
    }

    uint64_t pre_output = (((uint64_t)R) << 32) | (uint64_t)L;
    uint64_t inv_init_perm_res = inverse_initial_permutation(pre_output);

    return inv_init_perm_res;
}

// Function to perform DES encryption
uint64_t des_encrypt(uint64_t input, uint64_t key) {
    return des(input, key, 'e');
}

// Function to perform DES decryption
uint64_t des_decrypt(uint64_t input, uint64_t key) {
    return des(input, key, 'd');
}

void gen_des_key(const char *filename) {
    FILE *key_file = fopen(filename, "wb");
    if (key_file == NULL) {
        perror("Error opening key file");
        exit(EXIT_FAILURE);
    }

    srand(time(NULL));

    uint8_t key[DES_BLOCK_SIZE];
    for (int i = 0; i < DES_BLOCK_SIZE; i++) {
        key[i] = rand() % 256;
    }

    // Print the generated key for debugging
    printf("Generated Key:");
    for (int i = 0; i < DES_BLOCK_SIZE; i++) {
        printf(" %02x", key[i]);
    }
    printf("\n");

    fwrite(key, 1, DES_BLOCK_SIZE, key_file);
    fclose(key_file);
}

uint8_t* read_des_key(const char *filename) {
    printf("Opening file: %s\n", filename);
    FILE *key_file = fopen(filename, "rb");
    if (key_file == NULL) {
        perror("Error opening key fileeeee");
        exit(EXIT_FAILURE);
    }

    uint8_t *key = (uint8_t*)malloc(DES_BLOCK_SIZE);
    if (key == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    fread(key, 1, DES_BLOCK_SIZE, key_file);
    fclose(key_file);


    return key;
}
/*
// Function to encrypt a file using DES
void des_encrypt_file(FILE *input_fp, const char *output_file) {
    FILE *encryptedFile = fopen(output_file, "wb");
    if (!encryptedFile) {
        printf("Error opening output file for writing.\n");
        return;
    }
    gen_des_key("des_key.txt");
    uint8_t inputBuffer[DES_BLOCK_SIZE];
    uint8_t outputBuffer[DES_BLOCK_SIZE];
    printf("1");
    uint64_t *key = (uint64_t *) read_des_key("des_key.txt");
    // Read input file in blocks and encrypt each block
    while (fread(inputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, input_fp) == DES_BLOCK_SIZE) {
        uint64_t inputBlock = *((uint64_t*)inputBuffer);
        uint64_t encryptedBlock = des_encrypt(inputBlock, (uint64_t) key); // Call your DES encryption function
        *((uint64_t*)outputBuffer) = encryptedBlock;
        fwrite(outputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, encryptedFile);
    }

    fclose(encryptedFile);
}*/
/*
void des_encrypt_file(FILE *input_fp, const char *output_file) {
    FILE *encryptedFile = fopen(output_file, "wb");
    if (!encryptedFile) {
        printf("Error opening output file for writing.\n");
        return;
    }


    uint64_t key = 0x133457799BBCDFF1; // Example key, replace with your key
    // Generate or read DES key here

    uint8_t inputBuffer[DES_BLOCK_SIZE];
    uint8_t outputBuffer[DES_BLOCK_SIZE];

    // Read input file in blocks and encrypt each block
    size_t bytesRead;
    while ((bytesRead = fread(inputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, input_fp)) > 0) {
        if (bytesRead < DES_BLOCK_SIZE) {
            // Pad the last block if necessary
            for (size_t i = bytesRead; i < DES_BLOCK_SIZE; ++i) {
                inputBuffer[i] = 0; // You may want to choose a proper padding strategy
            }
        }

        uint64_t inputBlock = *((uint64_t*)inputBuffer);
        uint64_t encryptedBlock = des_encrypt(inputBlock, key); // Call your DES encryption function
        *((uint64_t*)outputBuffer) = encryptedBlock;

        fwrite(outputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, encryptedFile);
    }

    fclose(encryptedFile);
}*/

void des_encrypt_file(FILE *input_fp, const char *output_file) {
    FILE *encryptedFile = fopen(output_file, "wb");
    if (!encryptedFile) {
        printf("Error opening output file for writing.\n");
        return;
    }

    gen_des_key("key_file.txt");
    // Generate or read DES key
    uint8_t *key = read_des_key("des_key.txt"); // or gen_des_key(key_file);

    uint8_t inputBuffer[DES_BLOCK_SIZE];
    uint8_t outputBuffer[DES_BLOCK_SIZE];

    // Read input file in blocks and encrypt each block
    size_t bytesRead;
    while ((bytesRead = fread(inputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, input_fp)) > 0) {
        if (bytesRead < DES_BLOCK_SIZE) {
            // Pad the last block if necessary
            for (size_t i = bytesRead; i < DES_BLOCK_SIZE; ++i) {
                inputBuffer[i] = 0; // You may want to choose a proper padding strategy
            }
        }

        uint64_t inputBlock = *((uint64_t*)inputBuffer);
        uint64_t encryptedBlock = des_encrypt(inputBlock, *((uint64_t*)key)); // Call your DES encryption function with the key
        *((uint64_t*)outputBuffer) = encryptedBlock;

        fwrite(outputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, encryptedFile);
    }

    fclose(encryptedFile);
    free(key); // Free dynamically allocated memory for the key
}
/*
// Function to decrypt a file using DES
void des_decrypt_file(FILE *input_fp, const char *output_file) {
    FILE *decryptedFile = fopen(output_file, "wb");
    if (!decryptedFile) {
        printf("Error opening output file for writing.\n");
        return;
    }

    uint8_t inputBuffer[DES_BLOCK_SIZE];
    uint8_t outputBuffer[DES_BLOCK_SIZE];

    uint64_t *key = (uint64_t *) read_des_key("des_key.txt");

    // Read input file in blocks and decrypt each block
    while (fread(inputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, input_fp) == DES_BLOCK_SIZE) {
        uint64_t inputBlock = *((uint64_t*)inputBuffer);
        uint64_t decryptedBlock = des_decrypt(inputBlock, (uint64_t) key); // Call your DES decryption function
        *((uint64_t*)outputBuffer) = decryptedBlock;
        fwrite(outputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, decryptedFile);
    }

    fclose(decryptedFile);
}*/

void des_decrypt_file(FILE *input_fp, const char *output_file) {
    FILE *decryptedFile = fopen(output_file, "wb");
    if (!decryptedFile) {
        printf("Error opening output file for writing.\n");
        return;
    }

    // Load DES key from file
    uint8_t *key = read_des_key("des_key.txt");

    uint8_t inputBuffer[DES_BLOCK_SIZE];
    uint8_t outputBuffer[DES_BLOCK_SIZE];

    // Read input file in blocks and decrypt each block
    size_t bytesRead;
    while ((bytesRead = fread(inputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, input_fp)) > 0) {
        uint64_t inputBlock = *((uint64_t*)inputBuffer);
        uint64_t decryptedBlock = des_decrypt(inputBlock, *((uint64_t*)key)); // Call your DES decryption function with the key

        // If it's the last block, remove padding
        if (bytesRead < DES_BLOCK_SIZE) {
            // Remove padding from the last block
            // You need to implement a proper padding strategy and handle it accordingly
            // This is just an example of removing zero padding
            while (decryptedBlock & 0xFF == 0) {
                decryptedBlock >>= 8;
            }
        }

        *((uint64_t*)outputBuffer) = decryptedBlock;
        fwrite(outputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, decryptedFile);
    }

    fclose(decryptedFile);
    free(key); // Free dynamically allocated memory for the key
}
/*
void des_decrypt_file(FILE *input_fp, const char *output_file) {
    FILE *decryptedFile = fopen(output_file, "wb");
    if (!decryptedFile) {
        printf("Error opening output file for writing.\n");
        return;
    }

    uint8_t inputBuffer[DES_BLOCK_SIZE];
    uint8_t outputBuffer[DES_BLOCK_SIZE];

    // Load DES key from file
    uint64_t key = 0x133457799BBCDFF1; // Example key, replace with your key

    // Read input file in blocks and decrypt each block
    size_t bytesRead;
    while ((bytesRead = fread(inputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, input_fp)) > 0) {
        uint64_t inputBlock = *((uint64_t*)inputBuffer);
        uint64_t decryptedBlock = des_decrypt(inputBlock, key); // Call your DES decryption function

        // If it's the last block, remove padding
        if (bytesRead < DES_BLOCK_SIZE) {
            // Remove padding from the last block
            // You need to implement a proper padding strategy and handle it accordingly
            // This is just an example of removing zero padding
            while (decryptedBlock & 0xFF == 0) {
                decryptedBlock >>= 8;
            }
        }

        *((uint64_t*)outputBuffer) = decryptedBlock;
        fwrite(outputBuffer, sizeof(uint8_t), DES_BLOCK_SIZE, decryptedFile);
    }

    fclose(decryptedFile);
}*/

