#ifndef UTILS_H
#define UTILS_H

#include "types.h"

void cache_flusher();

void print_bits(mpz_class n);

void matrix_rand_2exp(matrix_z &mat, int l);

void rand_prime(mpz_class &rlt, int l);

int mod_pos(int x, int d);

int mod_bit(int x);

void mod_prime(mpz_class &x, const mpz_class &p);

void mod_2exp(mpz_class &x, int n);

void mod_2exp(matrix_z &mat, int n);

inline int extract_bit(mpz_class n, int k) {
    return n.get_ui() >> k & 1;
}
//wine, linnerud, (breast) cancer, digits, diabetes, boston  (n, d)
const int param_nd[5][2] = {{9,8}, {13,3}, {13,13}, {15,4}, {57,17}};
                            // {10, 28},//28 is too big
                            // {13, 30}};//d = 30 is too big
//inline int extract_bit(int)
#endif