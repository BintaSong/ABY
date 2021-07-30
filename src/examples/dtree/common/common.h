#ifndef COMMON_H
#define COMMON_H

#include <gmpxx.h>
#include <gmp.h>
#include <cmath>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "common_src/config.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../examples/lowmc/common/LowMC.h"
#include <cassert>

//how to initial time?
// auto start = std::chrono::steady_clock::now(), stop = std::chrono::steady_clock::now();
// #define CLOCK_START {start = std::chrono::steady_clock::now();}
// #define CLOCK_END {stop = std::chrono::steady_clock::now();}
// #define ELAPSED std::chrono::duration<double, std::nano>(stop - start).count()

void str2bin(const std::string& in, unsigned char out[]);
void aes_xor_class_plain(BYTE in[16], mpz_class& plain);
void mpz_xor_mask(block mask, uint16_t mask_len, mpz_class& plain); 
void mpz_xor_mask(BYTE *mask, uint16_t mask_len, mpz_class& plain);

void deconcatenate(mpz_class concate_result, mpz_class& de_concate_result1);
void deconcatenate(mpz_class concate_result, uint64_t& de_concate_result1);
void deconcatenate(mpz_class concate_result, uint64_t& de_concate_result0, uint64_t& de_concate_result1);
uint64_t mpz2uint64(mpz_class z);
uint64_t mpz2uint64_lowmc(mpz_class z);
void FSSFeatureRead(e_role role, string file1, string file2, vector<int>& zeroOrOne, int num, int dim);
void OTKRead(string filename, vector<uint64_t>& OTK, int dim);
void FSSTreeRead(e_role role, string file1, string file2, vector<int>& zeroOrOne, int num);


#endif