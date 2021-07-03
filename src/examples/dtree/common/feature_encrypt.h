#ifndef FEATURE_ENCRYPT_H
#define FEATURE_ENCRYPT_H

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
#include "test_oblivious_read.h"
#include "pAES.h"
#include "common.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/sharing/yaoserversharing.h"

void ss_real_feature(int num);
node_tuple_mz return_feature(uint64_t num, uint64_t featureMax);
//this is for test, each evalue of attribute is fixed
node_tuple_mz return_fixed_feature(uint64_t featureDim, uint64_t featureMax);
void print_ss_tuple_mz(node_tuple_mz& tuple);
void prf_aes_128_by_key(uint64_t num, BYTE key[16], node_tuple_mz & feature);
void prf_aes_128_decrypt_by_key_feature(uint64_t num, mpz_class &result);

#endif