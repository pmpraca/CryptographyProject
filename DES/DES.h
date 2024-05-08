//
// Created by Praça on 05/05/2024.
//

#ifndef CRYPTOGRAPHYPROJECT_DES_H
#define CRYPTOGRAPHYPROJECT_DES_H

#include <stdint.h>

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
static uint64_t inverse_initial_permutation(uint64_t input);
void initial_key_schedule(uint64_t key, uint32_t *C, uint32_t *D);
void calculate_sub_keys(uint32_t C, uint32_t D, uint64_t *sub_keys);
uint32_t calculate_f(uint32_t R, uint64_t *sub_key, char mode, int iteration_i);
uint64_t des_decrypt(uint64_t input, uint64_t key);
uint64_t des_encrypt(uint64_t input, uint64_t key);
uint64_t des(uint64_t input, uint64_t key, char mode);

#endif //CRYPTOGRAPHYPROJECT_DES_H
