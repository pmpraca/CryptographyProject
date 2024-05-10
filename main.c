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
#include "string.h"

int main() {
    char input_file[256];
    char output_file[256];
    char option[3];
    int method = 0;

    /*
    printf("Enter input file: ");
    scanf("%s", input_file);

    // Open input and output files
    FILE *input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        printf("Error opening input file.\n");
        return 1;
    }

    printf("You want to Encrypt or Decrypt? ");
    scanf("%s", option);

    if(strcmp(option, "e") == 0){
        method = 0;
    } else if (strcmp(option, "d") == 0){
        method = 1;
    } else {
        printf("Invalid Option!");
        fclose(input_fp);
        return 1;
    }

    printf("Enter Output File: ");
    scanf("%s", output_file);

    //encrypt
    if(method == 0) {
        aes_encrypt_file(input_fp,output_file);
    } else if (method == 1){
        aes_decrypt_file(input_fp,output_file);
    }
*/
/*

    printf("\nRSA\n");

    printf("Enter input file: ");
    scanf("%s", input_file);
    // Open input and output files
    FILE *input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        printf("Error opening input file.\n");
        return 1;
    }

    printf("You want to Encrypt or Decrypt? ");
    scanf("%s", option);
    if(strcmp(option, "e") == 0){
        method = 0;
    } else if (strcmp(option, "d") == 0){
        method = 1;
    } else {
        printf("Invalid Option!");
        fclose(input_fp);
        return 1;
    }

    printf("Enter Output File: ");
    scanf("%s", output_file);

    //encrypt
    if(method == 0) {
        encrypt(input_fp,output_file);
    } else if (method == 1){
        decrypt(input_fp,output_file);
    }*/
/*
    int message = 50; // Example message
    printf("Message to be encrypted: %d\n", message);

    // Encryption
    int ciphertext = encrypt(message);
    printf("Ciphertext: %d\n", ciphertext);

    // Decryption
    int decryptedtext = decrypt(ciphertext);
    printf("Decrypted text: %d\n", decryptedtext);
*/
    printf("\nDESSS TIMEEEEEEE\n");

    printf("Enter input file: ");
    scanf("%s", input_file);
    // Open input and output files
    FILE *input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        printf("Error opening input fileeeee.\n");
        return 1;
    }

    printf("You want to Encrypt or Decrypt? ");
    scanf("%s", option);
    if(strcmp(option, "e") == 0){
        method = 0;
    } else if (strcmp(option, "d") == 0){
        method = 1;
    } else {
        printf("Invalid Option!");
        fclose(input_fp);
        return 1;
    }

    printf("Enter Output File: ");
    scanf("%s", output_file);

    //encrypt
    if(method == 0) {
        des_encrypt_file(input_fp,  output_file);
    } else if (method == 1){
        des_decrypt_file(input_fp,  output_file);
    }
/*
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
*/
    return 0;
}





