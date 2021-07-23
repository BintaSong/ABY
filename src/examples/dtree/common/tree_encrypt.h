#ifndef TREE_ENCRYPT_H
#define TREE_ENCRYPT_H

#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
// #include <fstream>
#include <cmath>
#include <vector>
#include <gmpxx.h>
#include <gmp.h>
#include <cstdio>
#include <iterator>
#include <algorithm>
#include "common_src/secret_sharing.h"
#include "common_src/utils.h"
#include "common_src/config.h"
#include "tree_read_from_file.h"
#include "test_oblivious_read.h"
#include "pAES.h"
//#include "LowMC.h"
#include "common.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/sharing/yaoserversharing.h"

void ss_real_tree(DecTree& tree);
std::vector<node_tuple_mz> return_tree(DecTree& tree, uint64_t(&array)[5]);

std::vector<node_tuple_mz> encrypt_tree(const DecTree& tree, uint64_t *root_node);

//void ss_real_tree(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing comparesharing, uint32_t keybitlen, DecTree& tree);
//std::vector<node_tuple_mz> return_tree(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing comparesharing, uint32_t keybitlen, DecTree& tree);

void print_vector_ss_tuple_mz(std::vector<node_tuple_mz>& tuple);

void concatenate(std::vector<node_tuple_mz>& treeV, std::vector<node_tuple_mz>& encryptedTreeV);

void concatenate(std::vector<node_tuple_mz>& treeV, const uint16_t block_size, std::vector<node_tuple_mz>& encryptedTreeV); 

void deconcatenate(mpz_class blocks[], uint16_t n_blocks, uint64_t nodes[]); 

void deconcatenate(mpz_class concate_result, mpz_class& de_concate_result0, mpz_class& de_concate_result1);

void prf_vector_aes_128_by_key(int tag, uint64_t num, BYTE key[16], 
std::vector<node_tuple_mz>& encryptedTreeV);

void prf_aes_128_decrypt_by_key(int tag, uint64_t num, mpz_class &result);

void prf_vector_lowmc_by_key(int tag, uint64_t num, BYTE* key, size_t key_length, 
std::vector<node_tuple_mz>& encryptedTreeV);

void prf_lowmc_decrypt_by_key(int tag, uint64_t num, mpz_class &result);

#endif