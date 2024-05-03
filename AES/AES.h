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
static const uint8_t SBox[256] = {
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


unsigned char galois_multiplication(unsigned char a, int b);

void ShiftRow(unsigned char *state, int nbr);

uint8_t xtime(uint8_t tm);

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

void SubBytes(uint8_t *state) {
    for (int i = 0; i < AES_COLUMNS * 4; i++) {
        state[i] = SBox[state[i]];
    }
}
/*
void ShiftRows(uint8_t *state) {
    uint8_t temp[AES_COLUMNS * 4];

    for (int i = 0; i < AES_COLUMNS; i++) {
        for (int j = 0; j < 4; j++) {
            temp[i + j * AES_COLUMNS] = state[i * AES_COLUMNS + (j + i) % AES_COLUMNS];
        }
    }

    for (int i = 0; i < AES_COLUMNS * 4; i++) {
        state[i] = temp[i];
    }
}*/

// ShiftRows function
void ShiftRows(uint8_t *state) {
    uint8_t temp;

    // Row 1: No shift
    // Row 2: Left shift by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 3: Left shift by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 4: Left shift by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// MixColumns function
void MixColumns(uint8_t *state) {
    uint8_t tmp, tm, t;
    for (int i = 0; i < AES_COLUMNS; ++i) {
        t = state[i * 4];
        tmp = state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        tm = state[i * 4] ^ state[i * 4 + 1];
        tm = xtime(tm);
        state[i * 4] ^= tm ^ tmp;
        tm = state[i * 4 + 1] ^ state[i * 4 + 2];
        tm = xtime(tm);
        state[i * 4 + 1] ^= tm ^ tmp;
        tm = state[i * 4 + 2] ^ state[i * 4 + 3];
        tm = xtime(tm);
        state[i * 4 + 2] ^= tm ^ tmp;
        tm = state[i * 4 + 3] ^ t;
        tm = xtime(tm);
        state[i * 4 + 3] ^= tm ^ tmp;
    }
}

uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/*
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
}*/

/*
const uint8_t mul2[] = {
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
        0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
        0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
        0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
        0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
        0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
        0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
        0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
        0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
        0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
        0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
        0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe
};

const uint8_t mul3[] = {
        0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
        0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
        0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
        0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
        0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69,
        0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
        0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59,
        0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
        0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
        0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
        0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9,
        0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
        0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9,
        0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
        0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
        0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81
};

uint8_t mul(uint8_t a, uint8_t b) {
    if (a == 0x01)
        return b;
    else if (a == 0x02)
        return mul2[b];
    else if (a == 0x03)
        return mul3[b];
    else
        return 0x00;
}

void MixColumns(uint8_t *state) {
    uint8_t tmp[4 * AES_COLUMNS];

    for (int c = 0; c < AES_COLUMNS; c++) {
        tmp[c * AES_COLUMNS] = mul(0x02, state[c * AES_COLUMNS]) ^ mul(0x03, state[1 + c * AES_COLUMNS]) ^ state[2 + c * AES_COLUMNS] ^ state[3 + c * AES_COLUMNS];
        tmp[1 + c * AES_COLUMNS] = state[c * AES_COLUMNS] ^ mul(0x02, state[1 + c * AES_COLUMNS]) ^ mul(0x03, state[2 + c * AES_COLUMNS]) ^ state[3 + c * AES_COLUMNS];
        tmp[2 + c * AES_COLUMNS] = state[c * AES_COLUMNS] ^ state[1 + c * AES_COLUMNS] ^ mul(0x02, state[2 + c * AES_COLUMNS]) ^ mul(0x03, state[3 + c * AES_COLUMNS]);
        tmp[3 + c * AES_COLUMNS] = mul(0x03, state[c * AES_COLUMNS]) ^ state[1 + c * AES_COLUMNS] ^ state[2 + c * AES_COLUMNS] ^ mul(0x02, state[3 + c * AES_COLUMNS]);
    }

    for (int i = 0; i < 4 * AES_COLUMNS; i++) {
        state[i] = tmp[i];
    }
}*/

//void AddRoundKey(uint8_t *state, uint8_t *roundKey) {
//    for (int i = 0; i < AES_COLUMNS * 4; i++) {
//        state[i] ^= roundKey[i];
//    }
//}

void AddRoundKey(unsigned char *state, const unsigned char *roundKey)
{
    int i;
    for (i = 0; i < 16; i++)
        state[i] = state[i] ^ roundKey[i];
}
/*
// 4 Subprocesses functions:

// Transformation in the Cipher that processes the State using a non­
// linear byte substitution table (S-box) that operates on each of the
// State bytes independently.




// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets.



*/
// Transformation in the Cipher that takes all of the columns of the
// State and mixes their data (independently of one another) to
// produce new columns.
/*
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
*/
/*
// Transformation in the Cipher and Inverse Cipher in which a Round
// Key is added to the State using an XOR operation. The length of a
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes).

*/

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

void print_key(const uint8_t *key) {
    for (int i = 0; i < 16; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");
}

void print_state(const char *label, const uint8_t *state) {
    printf("%s ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02X", state[i]);
    }
    printf("\n");
}

void Cipher(unsigned char *in, unsigned char *out, unsigned char *w) {
    uint8_t state[4 * AES_COLUMNS];

    // 1. Initialize the State
    for (int i = 0; i < AES_COLUMNS; i++) {
        for (int j = 0; j < AES_COLUMNS; j++) {
            state[i + j * 4] = in[i + j * AES_COLUMNS];
        }
    }

    // 2. Initial Round Key Addition
    AddRoundKey(state, w);

    printf("round[%2d].input   ", 0);
    print_state("", in);

    printf("round[%2d].k_sch   ", 0);
    print_state("", w);

    // 3. Main Rounds
    for (int round = 1; round <= AES_ROUNDS-1 ; round++) {
        printf("round[%2d].start   ", round);
        print_state("", state);

        // SubBytes
        SubBytes(state);
        printf("round[%2d].s_box   ", round);
        print_state("", state);

        // ShiftRows
        ShiftRows(state);
        printf("round[%2d].s_rows  ", round);
        print_state("", state);

        // MixColumns
        MixColumns(state);
        printf("round[%2d].m_cols  ", round);
        print_state("", state);

        // AddRoundKey
        AddRoundKey(state,w + (round) * 16);
        printf("round[%2d].k_sch    ", round +1);
        print_key(w + (round + 1) * 16);
    }



    // SubBytes
    SubBytes(state);
    printf("round[%2d].s_box   ", 10);
    print_state("", state);

    // ShiftRows
    ShiftRows(state);
    printf("round[%2d].s_rows  ", 10);
    print_state("", state);

    // AddRoundKey
    AddRoundKey(state,w + AES_ROUNDS * 16);


    // 5. Output Assignment
    for (int i = 0; i < AES_COLUMNS; i++) {
        for (int j = 0; j < 4; j++) {
            out[i + j * AES_COLUMNS] = state[i * 4 + j];
        }
    }

    // Final Output
    printf("round[%2d].OUTPUT ", AES_ROUNDS);
    print_state("", state);

    // Final Output
    printf("round[%2d].OUTPUT2 ", AES_ROUNDS);
    print_state("", out);
}




#endif //CRYPTOGRAPHYPROJECT_AES_H
