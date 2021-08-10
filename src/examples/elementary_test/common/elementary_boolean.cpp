/**
 \file 		elementary_boolean.cpp
 \author 	bintasong@gmail.com
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
 \brief		Implementation of the Inner Product using ABY Framework.
 */

#include "elementary.h"
#include "../../../abycore/sharing/sharing.h"

std::vector<uint32_t> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<uint32_t> res;

    while ((pos_end = s.find (delimiter, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (std::stoi(token));
		//std::cout<< std::stoi(token)<<std::endl;
    }

    res.push_back(std::stoi(s.substr(pos_start)));
	//std::cout<< std::stoi(s.substr(pos_start))<<std::endl;
    return res;
}

int32_t test_elementary_boolean(e_role role, const std::string& address, uint32_t port, seclvl seclvl,
		uint32_t numbers, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg) {

	/**
	 Step 1: Create the ABYParty object which defines the basis of all the
	 operations which are happening.	Operations performed are on the
	 basis of the role played by this object.
	 */
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg, 6553600);

	/**
	 Step 2: Get to know all the sharing types available in the program.
	 */
	std::vector<Sharing*>& sharings = party->GetSharings();

	/**
	 Step 3: Create the circuit object on the basis of the sharing type
	 being inputed.
	 */
	ArithmeticCircuit* ac =
			(ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	BooleanCircuit* bc =
			(BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	/**
	 Step 4: Creating the share objects - s_x_vec, s_y_vec which
	 are used as inputs to the computation. Also, s_out which stores the output.
	 */

	share *s_x_vec, *s_y_vec, *s_out;

	/**
	 Step 5: Allocate the xvals and yvals that will hold the plaintext values.
	 */
	uint32_t x, y;

	uint32_t output, v_sum = 0;

	std::vector<uint32_t> xvals(numbers);
	std::vector<uint32_t> yvals(numbers);

	uint32_t i;
	srand(0);

#if FILE_INPUT
	std::cout<< "\nReading inputs from file..." << std::endl;
	std::string input_file = role == SERVER ? "INPUT_boolean_0" : "INPUT_boolean_1";
	std::ifstream file_in(input_file.c_str()); // 打开状态保存文本
	if (!file_in.is_open()) {
		throw std::runtime_error(input_file + ": unable to read the input file");
	}
 	std::stringstream rand_buf;
    rand_buf << file_in.rdbuf();
	file_in.close();
	
	std::string input_str = rand_buf.str();
	if (role == SERVER) {
		xvals = split(input_str, " ");
		numbers = xvals.size(); // 根据文件中输入数据个数来确定输入的数据量
		for (int i = 0; i < numbers; i++) {
			std::cout << "\n xvals[" << i << "]" << " = " <<xvals[i] << std::endl;
		}
	}
	else {
		yvals = split(input_str, " ");
		numbers = yvals.size(); // 根据文件中输入数据个数来确定输入的数据量
		for (int i = 0; i < numbers; i++) {
			std::cout << "\n yvals[" << i << "]" << " = " <<yvals[i] << std::endl;
		}
	}
#else
	for (i = 0; i < numbers; i++) {

		x = rand() % (2);
		y = rand() % (2);

		//v_sum += x + y;

		xvals[i] = x;
		yvals[i] = y;

	}
#endif
	uint32_t out_bitlen = 32, out_nvals = numbers, *out_vals;
	double op_time;


//-------------------test XOR-------------------

std::cout << "\n -------------------test XOR-------------------" << std::endl;
	s_x_vec = bc->PutSIMDINGate(numbers, xvals.data(), 1, SERVER);
	s_y_vec = bc->PutSIMDINGate(numbers, yvals.data(), 1, CLIENT);
	s_out = bc->PutXORGate(s_x_vec, s_y_vec); //BuildAddCircuit(s_x_vec, s_y_vec, numbers, ac);

#if ELEMENTARY_DEBUG 
	share *s_add_input_x_share = bc->PutSharedOUTGate(s_x_vec);
	share *s_add_input_y_share = bc->PutSharedOUTGate(s_y_vec);
	share *s_add_output_share = bc->PutSharedOUTGate(s_out);
#endif

	s_out = bc->PutOUTGate(s_out, ALL);

	party->ExecCircuit();

	s_out->get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals);	

#ifndef FILE_INPUT
	// check correctness
	std::cout<< "\nCheking correctness of addtion..." << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		assert(out_vals[i] == (xvals[i]+yvals[i]));
		std::cout << out_vals[i] << ", " << xvals[i] << ", " << yvals[i] <<std::endl;
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;
#endif

#if ELEMENTARY_DEBUG
	uint32_t *in_x_share, *in_y_share, *out_share; 
	uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_add_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_add_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_add_output_share->get_clear_value_vec(&out_share, &out_bitlen, &out_nvals);	

	std::cout << "\n\nXOR input x share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nXOR input y share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nXOR result share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nXOR results: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " <<out_vals[i] << std::endl;
	}

	// free(in_x_share);
	// free(in_y_share);
	// free(out_share); 
#endif

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n ADD \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();
	// free(out_vals);




//-------------------test AND -------------------
std::cout << "\n -------------------test AND-------------------" << std::endl;
	s_x_vec = bc->PutSIMDINGate(numbers, xvals.data(), 1, SERVER);
	s_y_vec = bc->PutSIMDINGate(numbers, yvals.data(), 1, CLIENT);
	s_out = bc->PutANDGate(s_x_vec, s_y_vec); //BuildMulCircuit(s_x_vec, s_y_vec, numbers, bc);
	
#if ELEMENTARY_DEBUG 
	share *s_mul_input_x_share = bc->PutSharedOUTGate(s_x_vec);
	share *s_mul_input_y_share = bc->PutSharedOUTGate(s_y_vec);
	share *s_mul_output_share = bc->PutSharedOUTGate(s_out);
#endif
	
	s_out = bc->PutOUTGate(s_out, ALL);

	party->ExecCircuit();

	s_out->get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals);

#ifndef FILE_INPUT
	// check correctness
	std::cout<< "\nCheking correctness of multiplication...\t";
	for (uint32_t i = 0; i < numbers; i++) {
		assert(out_vals[i] == (xvals[i]*yvals[i]));
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;
#endif 

#if ELEMENTARY_DEBUG
	// uint32_t *in_x_share, *in_y_share, *out_share; 
	// uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_mul_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_mul_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_mul_output_share->get_clear_value_vec(&out_share, &out_bitlen, &out_nvals);	

	std::cout << "\n\nAND input x share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nAND input y share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nAND result share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nAND results: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " <<out_vals[i] << std::endl;
	}

	// free(in_x_share);
	// free(in_y_share);
	// free(out_share); 
#endif

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n AND \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();
	// free(out_vals);


//-------------------test CMP -------------------
std::cout << "\n -------------------test OR-------------------" << std::endl;
	s_x_vec = bc->PutSIMDINGate(numbers, xvals.data(), 1, SERVER);
	s_y_vec = bc->PutSIMDINGate(numbers, yvals.data(), 1, CLIENT);
	s_out = bc->PutORGate(s_x_vec, s_y_vec); //BuildCmpCircuit(s_x_vec, s_y_vec, numbers, bc);


#if ELEMENTARY_DEBUG
	share *s_cmp_input_x_share = bc->PutSharedOUTGate(s_x_vec);
	share *s_cmp_input_y_share = bc->PutSharedOUTGate(s_y_vec);
	share *s_cmp_output_share = bc->PutSharedOUTGate(s_out);
#endif

	s_out = bc->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	s_out->get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;

#ifndef FILE_INPUT
	// check correctness
	std::cout<< "\nCheking correctness of compare...\t "<< out_bitlen << ", " << out_nvals;
	for (uint32_t i = 0; i < numbers; i++) {
		//std::cout<< out_vals[i]  << " " << xvals[i] << " " << yvals[i] << " " <<  (xvals[i]>yvals[i]) <<std::endl;
		assert(out_vals[i] == (xvals[i]>yvals[i]));
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;
#endif 

#if ELEMENTARY_DEBUG
	// uint32_t *in_x_share, *in_y_share, *out_share; 
	// uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_cmp_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_cmp_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_cmp_output_share->get_clear_value_vec(&out_share, &out_bitlen, &out_nvals);	

	std::cout << "\n\nOR input x share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nOR input y share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nOR result share: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nOR results: " << std::endl;
	for (uint32_t i = 0; i < numbers; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " <<out_vals[i] << std::endl;
	}

	free(in_x_share);
	free(in_y_share);
	free(out_share);
#endif

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n OR \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();
	free(out_vals);

	delete party;

	return 0;
}


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
	test_elementary_boolean(role, address, port, seclvl, numbers, bitlen, nthreads, mt_alg);

	return 0;
}