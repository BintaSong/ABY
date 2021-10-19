//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"
#include "common/dtread.h"
#include "common/ftread.h"
#include "common/fss_or_ot.h"
#include "common/tree_feature.h"

extern gmp_randclass gmp_prn;
extern BYTE key1[];
extern BYTE key2[];
extern BYTE key3[];

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, string* filename, uint32_t* depth, uint32_t* dim, uint64_t* numNodes, uint32_t* secparam, string* address, uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			{ (void*) filename, T_STR, "f", "Input file, e.g. wine, boston, ... (provide either an input file or depth & dimension)", false, false },
			{ (void*) depth, T_NUM, "d", "Depth of tree, default: 4", false, false },
			{ (void*) dim, T_NUM, "n", "Dimension of feature vector, default: 8", false, false },
			{ (void*) numNodes, T_NUM, "m", "Number of Decision Nodes, default: 15", false, false },
			{ (void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
			{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			{ (void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	cout << endl;

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	const char *filename[8] = {
		"wine",
		"linnerud",
		"breast",
		"digits",
		"spambase",
		"diabetes",
		"boston",
		"mnist"
	};
	uint64_t ftDim[8] = {7, 3, 12, 47, 57, 10, 13, 784};


	e_role role;
	uint32_t bitlen = 64, nvals = 1, secparam = 128, nthreads = 1;
	seclvl seclvl = get_sec_lvl(secparam);
	uint16_t port = 7760;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	bool verbose = false;
	bool use_vec_ands = false;
	bool expand_in_sfe = false;
	bool client_only = false;
	e_sharing sharing = S_BOOL;
    e_mt_gen_alg mt_alg = MT_OT;
	timeval tbegin, tend;

	//------------Tree Params(currently, we only use dectree_rootdir)-------------
	uint32_t depth = 10;//***********1/2 modify here if testing other trees************
	string dectree_rootdir = "../../src/examples/dtree/UCI_dectrees/";//according to exe's location
	uint32_t featureVecDimension = 8; //defaults
	uint64_t numNodes = (1 << depth) - 1; // number of decision nodes
	string dectree_filename = "wine";
	read_test_options(&argc, &argv, &role, &bitlen, &dectree_filename, &depth, &featureVecDimension, &numNodes, &secparam, &address, &port, &test_op);

	//preprocessing fss
	uint64_t ind = 2;
	uint64_t r0 = 12345;
	uint64_t r1 = r0 ^ ind;

	//modify here if testing other trees
	int i = 7; 
	cout << "Testing..." << filename[i] << endl;

	//hiding the real depth of tree
	uint32_t depthHide = 0;
	
	
	//-----------fss_or_ot--------------
	uint64_t featureDim = 7;
	uint32_t testdepth = 5;

	/*(n,d)
	{wine, 7,5}
	{linnerud:3,6}
	{breast:12,7}
	{digits: 47,15}
	{spambase:57,17}
	{diabetes: 10, 28}
	{boston:13, 30}
	{mnist:784, 20}
	add dummies:
	{500,100}
	{1000, 50}
	{10000,50}
	{100000,50}
	*/
	
	if(role ==  SERVER){
		//strating tree evaluation
		// get_tree_and_feature(role, (char*) address.c_str(), port, seclvl, bitlen, nthreads, mt_alg, sharing, dectree_rootdir + filename[i], ftDim[i], r0, depthHide, nvals, verbose, use_vec_ands, expand_in_sfe, client_only);
		fssorot_feature(role, (char*) address.c_str(), port, seclvl, bitlen, nthreads, mt_alg, sharing, dectree_rootdir + filename[i], featureDim, r0, testdepth, nvals, verbose, use_vec_ands, expand_in_sfe, client_only);
	}else if(role == CLIENT){
		// get_tree_and_feature(role, (char*) address.c_str(), port, seclvl, bitlen, nthreads, mt_alg, sharing, dectree_rootdir + filename[i], ftDim[i], r1, depthHide, nvals, verbose, use_vec_ands, expand_in_sfe, client_only);// last five params are for AES
		fssorot_feature(role, (char*) address.c_str(), port, seclvl, bitlen, nthreads, mt_alg, sharing, dectree_rootdir + filename[i], featureDim, r0, testdepth, nvals, verbose, use_vec_ands, expand_in_sfe, client_only);
	}
	
	
	return 0;
}