#include "secret_sharing.h"

#include "utils.h"

extern gmp_randclass gmp_prn;

void ss_encrypt(int plain, int share[2])
{
	share[1] = mod_bit(rand());
	share[0] = mod_bit(plain - share[1]);
}

void ss_decrypt(int &plain, int share[2])
{
	plain = mod_bit(share[0] + share[1]);
}

void ss_encrypt(const mpz_class & plain, mpz_class share[2])
{
	share[1] = gmp_prn.get_z_bits(CONFIG_L);
	share[0] = plain - share[1];
    mod_2exp(share[0], CONFIG_L);
}

void ss_decrypt(mpz_class & plain, const mpz_class share[2])
{
	plain = share[0] - share[1];
    mod_2exp(plain, CONFIG_L);
}

void ss_encrypt(const matrix_z &plain, matrix_z share[2])
{
	matrix_rand_2exp(share[1], CONFIG_L);
	share[0] = plain - share[1];
    mod_2exp(share[0], CONFIG_L);
}

void ss_decrypt(matrix_z &plain, const matrix_z share[2])
{
	plain = share[0] + share[1];
    mod_2exp(plain, CONFIG_L);
}

void ss_encrypt_xor(matrix_z &plain, matrix_z share[2])
{
	matrix_rand_2exp(share[1], CONFIG_L);
	mpz_class *data1 = share[1].data();
	mpz_class *data0 = share[0].data();
	mpz_class *dataplain = plain.data();
	for (int i = 0, size = share[1].size(); i < size; ++i) {
		*(data0+i) = *(dataplain+i) ^ *(data1+i);
	}
    mod_2exp(share[0], CONFIG_L);
}

void ss_decrypt_xor(matrix_z &plain, matrix_z share[2])
{
	mpz_class *data1 = share[1].data();
	mpz_class *data0 = share[0].data();
	mpz_class *dataplain = plain.data();
	for (int i = 0, size = plain.size(); i < size; ++i) {
		*(dataplain+i) = *(data0+i) ^ *(data1+i);
	}
    mod_2exp(plain, CONFIG_L);
}

void ss_encrypt(const matrix_z &plain, matrix_z &share0, matrix_z &share1)
{
	matrix_rand_2exp(share1, CONFIG_L);
	share0 = plain - share1;
    mod_2exp(share0, CONFIG_L);
}

void ss_decrypt(matrix_z &plain, const matrix_z &share0, const matrix_z &share1)
{
	plain = share0 + share1;
    mod_2exp(plain, CONFIG_L);
}