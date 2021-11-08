#ifndef TREE_FEATURE_H
#define TREE_FEATURE_H

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
#include "common.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/sharing/yaoserversharing.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include "tree_encrypt.h"
#include "feature_encrypt.h"
#include "fss_com.h"
#include "aes_circuit.h"
//connection and communication
#include "sndrcv.h"

#include "crypto_party/crypto_party.h"
#include "crypto_party/paillier_party.h"

#include "../../../examples/lowmc/common/lowmccircuit.h"
#include "../../../examples/lowmc/common/LowMC.h"

void get_tree_and_feature(e_role role, char* address, uint16_t port, seclvl seclvl, 
                        uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, 
                        e_sharing sharing, string filename, uint64_t featureDim, 
                        uint64_t r, uint32_t depthHide, uint32_t nvals, 
                        [[maybe_unused]] bool verbose, bool use_vec_ands, 
                        bool expand_in_sfe, bool client_only);

void eval_dt_paillier(e_role role, char* address, uint16_t port, seclvl seclvl, 
                    uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, 
                    std::string filename, uint64_t featureDim);

void paillier_tree_encoding_test(e_role role, char* address, uint16_t port, seclvl seclvl, 
                        uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, 
                        e_sharing sharing, string filename, uint64_t featureDim, 
                        uint64_t r, uint32_t depthHide, uint32_t nvals, 
                        [[maybe_unused]] bool verbose, bool use_vec_ands, 
                        bool expand_in_sfe, bool client_only);

void paillier_test(e_role role, char* address, uint16_t port, seclvl seclvl, 
                        uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, 
                        e_sharing sharing, string filename, uint64_t featureDim, 
                        uint64_t r, uint32_t depthHide, uint32_t nvals, 
                        [[maybe_unused]] bool verbose, bool use_vec_ands, 
                        bool expand_in_sfe, bool client_only);
#endif