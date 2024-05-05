//
// Created by Praça on 11/04/2024.
//

#include <cstring>
#include "AES.h"


int main() {

    // Cipher key
    uint8_t cipherKey[AES_WORDS * 4] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    // Expanded key
    uint8_t expandedKey[AES_COLUMNS * AES_WORDS * (AES_ROUNDS + 1)];

    // Perform key expansion
    KeyExpansion(cipherKey, expandedKey);

    // Input input
    uint8_t input[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    // Output outputState
    uint8_t outputState[16];

    // Print initial state
    printf("PLAINTEXT:        ");
    print_state("", input);
    printf("KEY:              ");
    print_state("", cipherKey);

    // Encrypt the input
    Cipher(input, outputState, expandedKey);

    // Output
    printf("round[%2d].output  ", AES_ROUNDS);
    print_state("", outputState);

    return 0;
}




