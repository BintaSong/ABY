#include "fss_com.h"
/*
The server and the client can run fss separately. However, this makes no sense. 
This header and source are not used.

*/
void fssKeyGen(ServerKeyEq &k0, ServerKeyEq &k1, uint64_t a, Fss& fClient, Fss& fServer){
	uint64_t b = 1;// a and b are 64 bits unsigned long
	// Initialize client, use 10 bits in domain as example
	initializeClient(&fClient, 10, 2);
	generateTreeEq(&fClient, &k0, &k1, a, b);
	initializeServer(&fServer, &fClient);
	cout << k0.s <<endl;
}

vector<int> fssEvaluate(ServerKeyEq k, uint64_t max, uint64_t num, Fss& fClient, Fss& fServer){
	mpz_class ans;
    bool tr;
	vector<int> zeroOrOne;
	int tmp;
    for(uint64_t i = 0; i < max; i++){
		tmp = 0;
		zeroOrOne.push_back(tmp);
	}
	for(uint64_t i = 0; i < num; i++){
		ans = evaluateEq(&fServer, &k, i, tr);
		zeroOrOne[i] = tr;
	}
    return zeroOrOne;
}