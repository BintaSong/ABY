#ifndef GLOBAL_DEFS_H
#define GLOBAL_DEFS_H

#include <chrono>
#include <string>
using namespace std;

#define CONFIG_L 64
#define CONFIG_C 128
#define CONFIG_M 193

typedef unsigned char BYTE;
#define NUM_BYTE 128/8

// hard-coded version
#define CONFIG_P 8522717063877521959
// void init_config();

// #define DTREE_DEBUG 1

#define DTREE_ENCRYPTED_BY_LOWMC 0 //0 is by AES

#define DTREE_FEAREAD_BY_OT 0 //0 is by FSS

#define DELTA_XOR 0 //0 is delta = a - b(working under N), 1 is delta = a ^ b(working under 2^n)
#endif