/**
 \file 		innerproduct_test.cpp
 \author	sreeram.sadasivam@cased.de
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
 \brief		Inner Product Test class implementation.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/elementary.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* numbers, uint32_t* secparam, std::string* address,
		uint32_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			  { (void*) numbers, T_NUM, "n",	"Number of elements for inner product, default: 128", false, false },
			  {	(void*) bitlen, T_NUM, "b", "Bit-length, default 16", false, false },
			  { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			  {	(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			  {	(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			  { (void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off",
					false, false } };

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint32_t) * 8));
		*port = (uint32_t) int_port;
	}

	return 1;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, numbers = 100, secparam = 128, nthreads = 1;
	uint32_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &numbers, &secparam, &address, &port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);

	// call test routine. set size with cmd-parameter -n <size>
	test_elementary_circuit(role, address, port, seclvl, numbers, bitlen, nthreads, mt_alg);

	return 0;
}

