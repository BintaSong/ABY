#include <stdio.h>
#include <gmp.h>
#include <time.h>

// mpz_urandomm.c
int main()
{
    clock_t time = clock();

    gmp_randstate_t grt;
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time);


    mpz_t key;
    mpz_init(key);
    
	for(int i = 0; i < 1000; i++){
		mpz_urandomb(key, grt, 64);
    	gmp_printf("%Zd\n", key);
	}
    mpz_clear(key);
}
