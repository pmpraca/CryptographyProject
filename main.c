#include <stdio.h>
#include "AES.h"
#include "RSA.h"
#include "DES.h"
#include "string.h"

void printHeader() {
    printf(" *********************\n");
    printf(" * Choose an Option: *\n");
    printf(" *********************\n");
}

void printOptions() {
    printf(" * [1] AES           *\n");
    printf(" * [2] DES           *\n");
    printf(" * [3] RSA           *\n");
    printf(" * [4] Exit          *\n");
    printf(" *********************\n");
    printf("\n Selection: ");
}

int getChoice() {
    int choice;
    while (1) {
        if (scanf("%d", &choice) != 1) {
            // Clear input buffer
            while (getchar() != '\n');
            printf("Invalid input. Please enter a number between 1 and 4: ");
        } else {
            break;
        }
    }
    return choice;
}

int main() {
    char input_file[256];
    char output_file[256];
    char option[3];
    int mode = 0;
    char algorithmChoosen[4];

    while (1) {
        printHeader();
        printOptions();

        int choice = getChoice();

        switch (choice) {
            case 1:
                strcpy(algorithmChoosen, "AES");
                printf("Algorithm chosen: AES\n");
                break;
            case 2:
                strcpy(algorithmChoosen, "DES");
                printf("Algorithm chosen: DES\n");
                break;
            case 3:
                strcpy(algorithmChoosen, "RSA");
                printf("Algorithm chosen: RSA\n");
                break;
            case 4:
                printf("Exiting...\n");
                return 0;
            default:
                printf("Invalid choice. Please enter a number between 1 and 4.\n");
                continue;
        }

        // Input File
        printf(" Enter input file: ");
        scanf("%s", input_file);

        // Open input file
        FILE *input_fp = fopen(input_file, "rb");
        if (!input_fp) {
            printf(" Error opening input file.\n");
            continue;
        }
        printf("\n");
        printf("*********************\n");
        printf(" * Choose an Option: *\n");
        printf(" *********************\n");
        printf(" * [e] Encrypt       *\n");
        printf(" * [d] Decrypt       *\n");
        printf(" *********************\n");

        scanf("%s", option);
        if (strcmp(option, "e") == 0) {
            mode = 0;
        } else if (strcmp(option, "d") == 0) {
            mode = 1;
        } else {
            printf("Invalid Option!\n");
            fclose(input_fp);
            continue;
        }

        // Output File
        printf("Enter Output File: ");
        scanf("%s", output_file);

        // Perform encryption/decryption based on the chosen algorithmChoosen
        if (strcmp(algorithmChoosen, "AES") == 0) {
            if (mode == 0) {
                aes_encrypt_file(input_fp, output_file);
            } else if (mode == 1) {
                aes_decrypt_file(input_fp, output_file);
            }
        } else if (strcmp(algorithmChoosen, "DES") == 0) {
            if (mode == 0) {
                des_encrypt_file(input_fp, output_file);
            } else if (mode == 1) {
                des_decrypt_file(input_fp, output_file);
            }
        } else if (strcmp(algorithmChoosen, "RSA") == 0) {
            if (mode == 0) {
                rsa_encrypt(input_fp, output_file);
            } else if (mode == 1) {
                rsa_decrypt(input_fp, output_file);
            }
        }

        fclose(input_fp);
    }

    return 0;
}
