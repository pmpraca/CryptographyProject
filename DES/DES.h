//
// Created by Praça on 05/05/2024.
//

#ifndef CRYPTOGRAPHYPROJECT_DES_H
#define CRYPTOGRAPHYPROJECT_DES_H

#include <stdint.h>
#include <stdio.h>
#define DES_BLOCK_SIZE 8
// Tables
static char IP[64];
static char inverse_IP[64];
static char E_bit_selection[64];
static char P[64];
static char Sboxes[8][64];
static char PC_1[64];
static char PC_2[64];
static char iteration_shift[64];

// DES Methods
static uint64_t initial_permutation(uint64_t input);
static uint64_t final_permutation(uint64_t input);
void permuted_key_split(uint64_t key, uint32_t *C, uint32_t *D);
void gen_sub_keys(uint32_t C, uint32_t D, uint64_t *sub_keys);
uint32_t f_function(uint32_t R, uint64_t *sub_key, char mode, int iteration_i);
uint64_t des_decrypt(uint64_t input, uint64_t key);
uint64_t des_encrypt(uint64_t input, uint64_t key);
uint64_t des(uint64_t input, uint64_t key, char mode);
uint8_t *read_des_key(const char *filename);
void gen_des_key(const char *filename);
void des_encrypt_file(FILE *input_file, const char *output_file);
void des_decrypt_file(FILE *input_file, const char *output_file);

#endif //CRYPTOGRAPHYPROJECT_DES_H
