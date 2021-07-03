#ifndef __TEST_OBLIVIOUS_READ__
#define __TEST_OBLIVIOUS_READ__

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <gmpxx.h>
#include <gmp.h>
#include <math.h>
#include "common_src/config.h"
#include "common_src/types.h"
#include "../fss/fss-common.h"
#include <limits.h>
#include <stdio.h>
#include <cstdlib>
#include <stdlib.h>
#include <algorithm>
#include <stdint.h> 
using namespace std;
void dotProductAdd(int tag, vector<ss_tuple_mz>& encryptedTreeV, mpz_class &r1, mpz_class &r2, mpz_class &r3);
void dotProductXor(int tag, vector<ss_tuple_mz>& encryptedTreeV, mpz_class &r1, mpz_class &r2, mpz_class &r3);
void readTreeFSS(int tag, vector<node_tuple_mz>& encryptedTreeV, mpz_class &r1, mpz_class &r2, mpz_class &r3);
//void readFeatureFSS(int &tag, node_tuple_mz encryptedFeature, int num, uint64_t shift, uint64_t & attrValue, string fssKeyFile);
void readFeatureFSS(node_tuple_mz encryptedFeature, int num, uint64_t shift, uint64_t & attrValue, string fssKeyFile);
#endif