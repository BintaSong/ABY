/**
 \file 		lowmc.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		LowMC implementation.
 */

#include "common/lowmccircuit.h"
#include <ENCRYPTO_utils/parse_options.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include "../../abycore/aby/abyparty.h"
#include "../../abycore/sharing/sharing.h"

#include <iomanip>



int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* nvals, uint32_t* secparam, std::string* address, uint16_t* port, uint32_t* statesize, uint32_t* keysize,
		uint32_t* sboxes, uint32_t* rounds, uint32_t* maxnumgates) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, { (void*) nvals, T_NUM, "n", "Number of parallel operations elements", false, false }, {
			(void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false }, { (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false }, { (void*) statesize, T_NUM, "t", "Statesize in bits", true, false }, { (void*) keysize, T_NUM,
					"k", "Keylength in bits", true, false }, { (void*) sboxes, T_NUM, "m", "#SBoxes per rounds", true, false },
			{ (void*) rounds, T_NUM, "o", "#Rounds", true, false }, { (void*) maxnumgates, T_NUM, "g", "Maximum number of gates in the circuit", false, false }
	};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 3, secparam = 128, nthreads = 1, statesize, sboxes, rounds, keysize, maxnumgates=0;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &nvals, &secparam, &address, &port, &statesize, &keysize, &sboxes, &rounds, &maxnumgates);

	crypto* crypt = new crypto(secparam, (uint8_t*) const_seed);
	// test_lowmc_circuit(role, address, port, nvals, nthreads, mt_alg, S_BOOL, statesize, keysize, sboxes, rounds, maxnumgates, crypt);
	
	// uint64_t test = 0x0102;
    // char str[33] = {};
    // memcpy(str, &test, 8);
    
    // for (int i = 0; i < 8; i++) {
    //     std::cout<< (int)str[i] <<std::endl;
    // }


	// FIXME: lowmc test over shared input and output
	LowMCParams param = {sboxes, keysize, statesize, keysize == 80 ? 64 : (uint32_t) 128, rounds};

	ABYParty* party;
	if(maxnumgates > 0)
		party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg, maxnumgates);
	else
		party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg);

	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* circ = sharings[S_BOOL]->GetCircuitBuildRoutine();
	
	// assert(circ->GetCircuitType() == C_BOOLEAN);

	BYTE test_input[param.blocksize/8 * nvals] = {0x0, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
	                                              0x0, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
												  0x0, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	BYTE test_mask[param.blocksize/8 * nvals] = {0x0};
	
	BYTE lowmc_key[] = {0x04, 0x03, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	// // uint256_t inputShare, input_mask = 123;
	BYTE outputShare[(uint64_t) ceil_divide(param.blocksize, 8) * nvals];

	std::cout << "\nTEST: "<< param.blocksize/8 *nvals << std::endl;

	// for(int i = 0; i < param.blocksize/8 * nvals; i++) {
	// 	std::cout << i << " : fuck you ";
	// }
	// std::cout <<std::endl; 

	for (uint16_t i = 0; i < nvals; i++) {
		std::cout << "\nTEST BLOCK: "<< i << std::endl;
		for (int j = ceil_divide(param.blocksize, 8) - 1; j >= 0; j--) {
			std::cout << std::bitset<8>(test_input[i * param.blocksize/8 + j]);
		}
	}
	// std::cout <<std::endl; 
	//sleep(3); 

	if (role == CLIENT) {
		test_lowmc_circuit_shared_input(role, nvals, crypt, S_BOOL, party, sharings, circ, &param, lowmc_key, test_input, outputShare, SERVER);
	}
	else {
		test_lowmc_circuit_shared_input(role, nvals, crypt, S_BOOL, party, sharings, circ, &param, lowmc_key, test_mask, outputShare, SERVER);
	}

	// for (int j = 0; j < ceil_divide(param.blocksize, 8) * nvals; j++) {
	// 	std::cout << std::bitset<8>(outputShare[j]);
	// }
	// std::cout<<std::endl;

	return 0;
}
