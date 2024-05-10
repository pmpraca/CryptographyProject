//
// Created by Praça on 11/04/2024.
//

#ifndef CRYPTOGRAPHYPROJECT_AES_H
#define CRYPTOGRAPHYPROJECT_AES_H

#define AES_COLUMNS 4
#define AES_WORDS 4
#define AES_ROUNDS 10
#define KEY_SIZE_128 16
#define AES_BLOCK_SIZE 16


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t galois_multiplication(uint8_t a, int i);
void SubBytes(uint8_t *state);
void ShiftRows(uint8_t *state);
void MixColumns(uint8_t *state);
void InvMixColumns(uint8_t *state);
void InvShiftRows(uint8_t *state);
void InvSubBytes(uint8_t *state);
void RotWord(uint8_t *temp);
void SubWord(uint8_t *temp);
void KeyExpansion(const uint8_t *cipherKey, uint8_t *expandedKey);
void print_key(const uint8_t *key);
void print_state(const char *label, const uint8_t *state);
void Cipher(unsigned char *in, unsigned char *out, unsigned char *w);
void InvCipher(unsigned char *in, unsigned char *out, unsigned char *w);
void AddRoundKey(unsigned char *state, const unsigned char *roundKey);
void gen_aes_key(const char *filename);
uint8_t* read_aes_key(const char *filename);
void aes_encrypt_file(FILE *input_fp, const char *output_file);
void aes_decrypt_file(FILE *input_fp, const char *output_file);
#endif //CRYPTOGRAPHYPROJECT_AES_H
