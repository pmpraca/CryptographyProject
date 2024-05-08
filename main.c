//
// Created by Praça on 05/05/2024.
//

//
// Created by Praça on 11/04/2024.
//



#include <stdio.h>
#include <stdint.h>
#include "AES.h"
#include "RSA.h"
#include "DES.h"

void readInputFromFile(const char* filename, uint8_t* input) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Read input data from file
    size_t bytes_read = fread(input, sizeof(uint8_t), 16, file); // Assuming input size is 16 bytes (AES state size)
    if (bytes_read != 16) {
        if (feof(file)) {
            fprintf(stderr, "Error: Unexpected end of file\n");
        } else if (ferror(file)) {
            perror("Error reading file");
        }
        fclose(file);
        return;
    }

    fclose(file);
}


int main() {

    // Cipher key
    //uint8_t cipherKey[AES_WORDS * 4] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Cipher key
    uint8_t cipherKey[AES_WORDS * 4];

    // Generate random key
    //generateRandomKey(cipherKey, sizeof(cipherKey));

    gen_key("aes_key.txt");

    readKeyFromFile("aes_key.txt", cipherKey);
    // Expanded key
    uint8_t expandedKey[AES_COLUMNS * AES_WORDS * (AES_ROUNDS + 1)];

    // Perform key expansion
    KeyExpansion(cipherKey, expandedKey);

    // Input input message
    //uint8_t input[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t input[16];
    readInputFromFile("message.txt", input);

    // Output outputState
    uint8_t outputState[16];

    // Output decrypted plaintext
    uint8_t decryptedOutput[16];

    // Print initial state
    printf("PLAINTEXT:        ");
    print_state("", input);
    printf("KEY:              ");
    print_state("", cipherKey);

    // Encrypt the input
    Cipher(input, outputState, expandedKey);

    // Decryption
    InvCipher(outputState, decryptedOutput, expandedKey);

    // Output
    printf("round[%2d].output  ", AES_ROUNDS);
    print_state("", outputState);

    // Print decrypted plaintext
    printf("Decrypted plaintext: ");
    print_state("", decryptedOutput);


    printf("\nRSAAA TIMEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEe\n");

    int message = 50; // Example message
    printf("Message to be encrypted: %d\n", message);

    // Encryption
    int ciphertext = encrypt(message);
    printf("Ciphertext: %d\n", ciphertext);

    // Decryption
    int decryptedtext = decrypt(ciphertext);
    printf("Decrypted text: %d\n", decryptedtext);

    printf("\nDESSS TIMEEEEEEE\n");

    uint64_t input2 = 0x0123456789ABCDEF;
    uint64_t key = 0x133457799BBCDFF1;

    // Encrypt the input
    uint64_t encrypted = des_encrypt(input2, key);

    // Decrypt the encrypted data
    uint64_t decrypted = des_decrypt(encrypted, key);

    // Print the results
    printf("Original input: 0x%016llX\n", input2);
    printf("Encrypted data: 0x%016llX\n", encrypted);
    printf("Decrypted data: 0x%016llX\n", decrypted);

    return 0;
}





