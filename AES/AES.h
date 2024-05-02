//
// Created by Praça on 11/04/2024.
//

#ifndef CRYPTOGRAPHYPROJECT_AES_H
#define CRYPTOGRAPHYPROJECT_AES_H

#include <cstdint>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define AES_COLUMNS 4
#define AES_WORDS 4 // 4, 6 or 8
#define AES_ROUNDS 10 // 10, 12 or 14
#define KEY_SIZE_128 16
#define KEY_SIZE_192 24
#define KEY_SIZE_256 32

// AES S-box
const uint8_t SBox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Define round constants for AES-128 key expansion
const uint8_t RoundConstants[10][4] = {
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {0x80, 0x00, 0x00, 0x00},
        {0x1B, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00}
};


void ShiftRow(unsigned char *string, int row);

unsigned char Multiply(unsigned char i, int i1);

void shiftRow(unsigned char *string, int i);

unsigned char galois_multiplication(unsigned char i, int i1);

// Function to set the cipher key
void set_cipher_key(uint8_t *key) {
    // Cipher key in hexadecimal format
    uint8_t cipher_key[KEY_SIZE_128] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    // Copy the cipher key to the provided key buffer
    for (size_t i = 0; i < KEY_SIZE_128; i++) {
        key[i] = cipher_key[i];
    }
}

// Function to generate a random AES-128 cipher key
void gen_key(uint8_t *key) {
    for (size_t i = 0; i < KEY_SIZE_128; i++) {
        key[i] = rand() % 256; // Gen rand byte
    }
}

// 4 Subprocesses functions:

// Transformation in the Cipher that processes the State using a non­
// linear byte substitution table (S-box) that operates on each of the
// State bytes independently.

void SubBytes(unsigned char *state)
{
    int i;
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (i = 0; i < 16; i++)
        state[i] = SBox[state[i]];
}



// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets.
void ShiftRows(unsigned char *state)
{
    int i;
    // iterate over the 4 rows and call shiftRow() with that row
    for (i = 0; i < 4; i++)
        ShiftRow(state + i * 4, i);
}

void ShiftRow(unsigned char *state, int nbr) {
    int i, j;
    unsigned char tmp;
    // each iteration shifts the row to the left by 1
    for (i = 0; i < nbr; i++)
    {
        tmp = state[0];
        for (j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}


// Transformation in the Cipher that takes all of the columns of the
// State and mixes their data (independently of one another) to
// produce new columns.

void MixColumns(unsigned char *column)
{
    unsigned char cpy[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);

    column[1] = galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);

    column[2] = galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);

    column[3] = galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}

unsigned char galois_multiplication(unsigned char a, int b) {
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}


// Transformation in the Cipher and Inverse Cipher in which a Round
// Key is added to the State using an XOR operation. The length of a
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes).

void AddRoundKey(unsigned char *state, const unsigned char *roundKey)
{
    int i;
    for (i = 0; i < 16; i++)
        state[i] = state[i] ^ roundKey[i];
}

// Transformation in the Inverse Cipher that is the inverse of MixColumns().
void InvMixColumns(){

};

// Transformation in the Inverse Cipher that is the inverse of ShiftRows().
void InvShiftRows(){

};

// Transformation in the Inverse Cipher that is the inverse of SubBytes().
void InvSubBytes(){

};


// Function used in the Key Expansion routine that takes a four-byte
// word and performs a cyclic permutation.
void RotWord(uint8_t *temp) {
    uint8_t temp_byte = temp[0]; // Store the first byte temporarily
    for (int i = 0; i < 3; i++) {
        temp[i] = temp[i + 1]; // Shift each byte to the left
    }
    temp[3] = temp_byte; // Place the first byte at the end
}

// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to
// produce an output word.
void SubWord(uint8_t *temp) {
    for (int i = 0; i < 4; i++) {
        temp[i] = SBox[temp[i]]; // Replace each byte with its corresponding value from the S-box
    }
}

// Key expansion function
void KeyExpansion(const uint8_t *cipherKey, uint8_t *expandedKey) {
    int Nk = AES_WORDS;
    int Nb = AES_COLUMNS;
    int Nr = AES_ROUNDS;
    int i, j;
    uint8_t temp[4], temp2[4];

    // Copy the Cipher Key to the beginning of the expanded key
    for (i = 0; i < Nk; i++) {
        for (j = 0; j < 4; j++) {
            expandedKey[i * 4 + j] = cipherKey[i * 4 + j];
        }
    }

    // Key expansion loop
    for (i = Nk; i < Nb * (Nr + 1); i++) {
        // Copy the previous word
        for (j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i - 1) * 4 + j];
        }


        // Print iteration number
        //printf("i: %d, ", i);

        // Print content of temp before RotWord operation
        //printf("temp: ");
        //for (int k = 0; k < 4; k++) {
        //    printf("%02X", temp[k]);
        //}



        if (i % Nk == 0) {

            // Apply RotWord operation
            RotWord(temp);

            //Debug RotWord
            // Print content of temp after RotWord operation
            //printf(" After RotWord(): ");
            //for (int k = 0; k < 4; k++) {
            //    printf("%02X", temp[k]);
            //}
            //printf("\n");

            // Apply SubWord operation to the result
            SubWord(temp);

            // Debug Subword
            //printf(" After SubWord(): ");
            //for (int k = 0; k < 4; k++) {
            //    printf("%02X", temp[k]);
            //}
            //printf("\n");

            // XOR with Rcon
            temp[0] ^= RoundConstants[i / Nk - 1][0]; // Subtract 1 to match the 0-based indexing of arrays

            //Debug After Xor with Rcon
            printf(" After Xor with Rcon: ");
            for (int k = 0; k < 4; k++) {
                printf("%02X", temp[k]);
            }
            printf("\n");
        }

        // XOR with the word Nk positions earlier
        for (j = 0; j < 4; j++) {
            expandedKey[i * 4 + j] = expandedKey[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

void print_state(const char *label, const uint8_t *state) {
    printf("%s ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02X", state[i]);
    }
    printf("\n");
}

void Cipher(const uint8_t *in, uint8_t *out, const uint8_t *w) {
    //uint8_t state[4][AES_COLUMNS];
    uint8_t state[4*AES_COLUMNS];
    // 1. Initialize the State
    // Copy the input into the state array
    /*for (int i = 0; i < AES_COLUMNS; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = in[i * 4 + j];
        }
    }
    */
    for (int i = 0; i < 4*AES_COLUMNS; i++) {
            state[i] = in[i];
    }
    // 2. Initial Round Key Addition
    AddRoundKey((uint8_t *) state, w);

    // 3. Main Rounds
    for (int round = 1; round < AES_ROUNDS; round++) {
        // SubBytes
        SubBytes((uint8_t *) state);
        //printf("round[%2d].s_box ", round);
        //print_state("",(uint8_t *)state);
        // ShiftRows
        ShiftRows((uint8_t *) state);

        // MixColumns
        MixColumns((uint8_t *) state);

        // AddRoundKey
        //AddRoundKey((uint8_t *) state, w + round * AES_COLUMNS * 4);
        AddRoundKey((uint8_t *) state, w + (round + 1) * AES_COLUMNS * 4);
        //printf("round[%2d].k_sch ", round);
        //print_state("",out);
    }

    // 4. Final Round
    // SubBytes
    SubBytes((uint8_t *) state);
    //printf("round[%2d].s_box ", 10);
    //print_state("",(uint8_t *)state);
    // ShiftRows
    ShiftRows((uint8_t *) state);

    // AddRoundKey
    AddRoundKey((uint8_t *) state, w + AES_ROUNDS * AES_COLUMNS * 4);

    // 5. Output Assignment
    // Copy the state to the output out
    /*for (int i = 0; i < AES_COLUMNS; i++) {
        for (int j = 0; j < 4; j++) {
            out[i * 4 + j] = state[j][i];
        }
    }
    */
    for (int i = 0; i < 4*AES_COLUMNS; i++) {

            out[i ] = state[i];
    }
}



#endif //CRYPTOGRAPHYPROJECT_AES_H
