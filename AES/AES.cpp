//
// Created by Praça on 11/04/2024.
//

#include <cstring>
#include "AES.h"


int main() {
/*
    // Cypher key
    //int K;

    // Cypher key buffer
    uint8_t K[KEY_SIZE_128];

    // Number of columns (32-bit words, standard = 4)
    int Nb = AES_COLUMNS;

    // Number of 32-bit words comprising the cipher key
    int Nk = AES_WORDS ;

    //Number of rounds, which is a function of Nk and Nb (which is fixed).
    int Nr = AES_ROUNDS;

    gen_key(K);

    printf("\n Generated AES-128 cipher key: ");
    for (size_t i = 0; i < KEY_SIZE_128; i++) {
        printf("%02X", K[i]); // Print each byte as a hexadecimal value
    }
    printf("\n");

    return 0;*/

    uint8_t K[KEY_SIZE_128];
    uint8_t expandedKey[176]; // 11 rounds * 16 bytes per round = 176 bytes

    //gen_key(K);

    // Set the cipher key from pdf
    set_cipher_key(K);

    printf("\n Generated AES-128 cipher key: ");
    for (size_t i = 0; i < KEY_SIZE_128; i++) {
        printf("%02X", K[i]); // Print each byte as a hexadecimal value
    }
    printf("\n");

    // Perform key expansion
    KeyExpansion(K, expandedKey);

    // Print the expanded key
    printf("\n Expanded key:\n");
    for (size_t i = 0; i < 176; i++) {
        printf("%02X", expandedKey[i]); // Print each byte as a hexadecimal value
    }
    printf("\n");

    // Print the expanded key with process details
    printf("\n i (dec)    temp        After           After        Rcon[i/Nk]    After XOR      w[i-Nk]     w[i]=temp XOR        \n");
    printf("                       RotWord()       SubWord()                  with Rcon                    w[i-Nk]             \n");
    printf("-------------------------------------------------------------------------------------------------------------------- \n");
    int i, j;
    for (i = 4; i <= 43; i++) { // Iterate for 44 iterations
        printf("%-3d        ", i);
        for (j = 0; j < 4; j++) {
            printf("%02X", expandedKey[(i - 1) * 4 + j]);
        }
        printf("     ");
        uint8_t temp[4];
        memcpy(temp, expandedKey + (i - 1) * 4, 4); // Copy the current word to temp for RotWord
        RotWord(temp);
        for (j = 0; j < 4; j++) {
            printf("%02X", temp[j]); // Print After RotWord
        }
        printf("     ");
        SubWord(temp); // Apply SubWord transformation
        for (j = 0; j < 4; j++) {
            printf("%02X", temp[j]); // Print After SubWord
        }
        printf("     ");
        printf("%02X%02X%02X%02X", RoundConstants[i / AES_WORDS - 1][0], RoundConstants[i / AES_WORDS - 1][1], RoundConstants[i / AES_WORDS - 1][2], RoundConstants[i / AES_WORDS - 1][3]);
        printf("        ");
        uint8_t temp2[4];
        memcpy(temp2, temp, 4); // Copy the result of SubWord for XOR operation
        temp2[0] ^= RoundConstants[i / AES_WORDS - 1][0];
        temp2[1] ^= RoundConstants[i / AES_WORDS - 1][1];
        temp2[2] ^= RoundConstants[i / AES_WORDS - 1][2];
        temp2[3] ^= RoundConstants[i / AES_WORDS - 1][3];
        for (j = 0; j < 4; j++) {
            printf("%02X", temp2[j]); // Print After XOR with Rcon
        }
        printf("     ");
        for (j = 0; j < 4; j++) {
            printf("%02X", expandedKey[(i - AES_WORDS) * 4 + j]);
        }
        printf("     ");
        for (j = 0; j < 4; j++) {
            printf("%02X", expandedKey[i * 4 + j]);
        }
        printf("\n");
    }



    return 0;
}
