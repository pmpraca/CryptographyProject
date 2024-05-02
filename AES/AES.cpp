//
// Created by Praça on 11/04/2024.
//

#include <cstring>
#include "AES.h"


/*int main() {
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

    return 0;//

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
}*/
/*
int main() {
    // Cipher key
    uint8_t cipherKey[AES_WORDS * 4] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // Expanded key
    uint8_t expandedKey[AES_COLUMNS * AES_WORDS * (AES_ROUNDS + 1)];

    // Perform key expansion
    KeyExpansion(cipherKey, expandedKey);

    // Print the expanded key with spaces every 4 bytes
    printf("Expanded key:\n");
    for (int i = 0; i < AES_COLUMNS * AES_WORDS * (AES_ROUNDS + 1); i++) {
        printf("%02X", expandedKey[i]); // Print each byte with leading zero if necessary
        if ((i + 1) % 4 == 0) {
            printf(" "); // Add a space after every 4 bytes
        }
        if ((i + 1) % 16 == 0) {
            printf("\n"); // Add a newline every 16 bytes for better readability
        }
    }
    printf("\n"); // Ensure a newline at the end of the output



    return 0;
}*/

void print_key(const uint8_t *key) {
    for (int i = 0; i < 16; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");
}

#include <stdio.h>
#include "aes.h"


int main() {
    // Cipher key
    uint8_t cipherKey[AES_WORDS * 4] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    // Expanded key
    uint8_t expandedKey[AES_COLUMNS * AES_WORDS * (AES_ROUNDS + 1)];

    // Perform key expansion
    KeyExpansion(cipherKey, expandedKey);

    // Input plaintext
    uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    // Output ciphertext
    uint8_t ciphertext[16];

    // Print initial state
    printf("PLAINTEXT: ");
    print_state("", plaintext);
    printf("KEY: ");
    print_state("", cipherKey);

    // Encrypt the plaintext
    Cipher(plaintext, ciphertext, expandedKey);

    /*
    // Print the intermediate states at each round
    for (int round = 0; round < AES_ROUNDS; round++) {
        if(round == 0) {
            // Print round information
            printf("round[%2d].input ", round);
            print_state("", plaintext);
        }

        printf("round[%2d].k_sch ", round);
        print_key(expandedKey + round * 16);

        printf("round[%2d].start ", round + 1);
        print_state("", plaintext);

        SubBytes(plaintext);
        printf("round[%2d].s_box  ", round + 1);
        print_state("", plaintext);

        printf("round[%2d].s_row  ", round + 1);
        ShiftRows(plaintext);
        print_state("", plaintext);

        if(round < AES_ROUNDS-1){
            printf("round[%2d].m_col  ", round + 1);
            MixColumns(plaintext);
            print_state("", plaintext);
        }

        AddRoundKey(plaintext, expandedKey + (round + 1) * 16);
    }*/

    // Final Round

    printf("round[%2d].k_sch ", AES_ROUNDS);
    print_key(expandedKey + AES_ROUNDS * 16);

    // Output
    printf("round[%2d].output ", AES_ROUNDS);
    print_state("", ciphertext);


    return 0;
}




