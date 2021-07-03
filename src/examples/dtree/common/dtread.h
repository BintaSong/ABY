#ifndef TEST_DTREAD_H
#define TEST_DTREAD_H

#include "common_src/config.h"
#include "tree_read_from_file.h"
#include "tree_encrypt.h"

using namespace std;

//void encrypt_tree(string filename);
void encrypt_tree(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing comparesharing, string filename);

#endif