/**
 \file 		abyfloat.cpp
 \author	daniel.demmler@ec-spride.de
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
 */

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/circuit/share.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <cassert>
#include <iomanip>
#include <iostream>
#include <math.h>

#include "elementary.h"

void read_test_options(int32_t* argcp, char*** argvp, e_role* role,
	uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
	uint16_t* port, int32_t* test_op, uint32_t* test_bit, double* fpa, double* fpb) {

	uint32_t int_role = 0, int_port = 0, int_testbit = 0;

	parsing_ctx options[] =
	{ {(void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
	{(void*) &int_testbit, T_NUM, "i", "test bit", false, false },
	{(void*) nvals, T_NUM, "n",	"Number of parallel operation elements", false, false },
	{(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,false },
	{(void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
	{(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
	{(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
	{(void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false },
	{(void*) fpa, T_DOUBLE, "x", "FP a", false, false },
	{(void*) fpb, T_DOUBLE, "y", "FP b", false, false }

	};

	if (!parse_options(argcp, argvp, options,
		sizeof(options) / sizeof(parsing_ctx))) {
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

	*test_bit = int_testbit;
}

std::vector<double> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<double> res;

    while ((pos_end = s.find (delimiter, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (std::stod(token));
		//std::cout<< std::stoi(token)<<std::endl;
    }

    res.push_back(std::stod(s.substr(pos_start)));
	//std::cout<< std::stoi(s.substr(pos_start))<<std::endl;
    return res;
}

void test_verilog_add64_SIMD(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads,
	e_mt_gen_alg mt_alg, e_sharing sharing, double afp, double bfp) {

	// for addition we operate on doubles, so set bitlen to 64 bits
	uint32_t bitlen = 64;

	std::string circuit_dir = "../../bin/circ/";

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);

	std::vector<Sharing*>& sharings = party->GetSharings();

	BooleanCircuit* circ = (BooleanCircuit*) sharings[sharing]->GetCircuitBuildRoutine();


// point a uint64_t pointer to the two input floats without casting the content
	uint64_t *aptr = (uint64_t*) &afp;
	uint64_t *bptr = (uint64_t*) &bfp;

	// use 32 bits for the sqrt example, so cast afp to float
	float afloat = (float) afp;
	uint32_t *afloatptr = (uint32_t*) &afloat;

	// for this example we need at least 4 values, since we do at least 4 example operations (see lines 100-102)
	assert(nvals > 3);

	// array of 64 bit values
	uint64_t avals[nvals];
	uint64_t bvals[nvals];

#if FILE_INPUT
	std::cout<< "\nReading inputs from file..." << std::endl;
	std::string input_file = role == SERVER ? "INPUT_float_0" : "INPUT_float_1";
	std::ifstream file_in(input_file.c_str()); // 打开状态保存文本
	if (!file_in.is_open()) {
		throw std::runtime_error(input_file + ": unable to read the input file");
	}
 	std::stringstream rand_buf;
    rand_buf << file_in.rdbuf();
	file_in.close();
	
	std::vector<double> xvals, yvals;

	std::string input_str = rand_buf.str();
	if (role == SERVER) {
		xvals = split(input_str, " ");
		nvals = xvals.size(); // 根据文件中输入数据个数来确定输入的数据量
		for (int i = 0; i < nvals; i++) {
			std::cout << "\n xvals[" << i << "]" << " = " <<xvals[i] << std::endl;
		}
	}
	else {
		yvals = split(input_str, " ");
		nvals = yvals.size(); // 根据文件中输入数据个数来确定输入的数据量
		for (int i = 0; i < nvals; i++) {
			std::cout << "\n yvals[" << i << "]" << " = " <<yvals[i] << std::endl;
		}
	}
	// std::cout << "\n hello " << std::endl;

	for (int i = 0; i < nvals; i++) {
		// std::cout << i << std::endl;
		if (role == SERVER) {
			avals[i] = *(uint64_t*) (xvals.data() + i);
			// memcpy(avals, xvals.data(), nvals*sizeof(double));
		}
		else {
			bvals[i] = *(uint64_t*) (yvals.data() + i);
		}
	}
#else
	// fill array with input values nvals times.
	std::fill(avals, avals + nvals, *aptr);
	std::fill(bvals, bvals + nvals, *bptr);

	// set some specific values differently for testing
	bvals[1] = 0;
	bvals[2] = *(uint64_t*) &afp;
	avals[3] = *(uint64_t*) &bfp;
#endif 

//------ FP addition gate ---------------
	// SIMD input gates
	share* ain = circ->PutSIMDINGate(nvals, avals, bitlen, SERVER);
	share* bin = circ->PutSIMDINGate(nvals, bvals, bitlen, CLIENT);

	// 32 bit input gate (non SIMD)
	//share* asqrtin = circ->PutINGate(afloatptr, 32, SERVER);

	share* sum = circ->PutFPGate(ain, bin, ADD, bitlen, nvals, no_status);
	share* add_out = circ->PutOUTGate(sum, ALL);

#if ELEMENTARY_DEBUG 
	share *s_add_input_x_share = circ->PutSharedOUTGate(ain);
	share *s_add_input_y_share = circ->PutSharedOUTGate(bin);
	share *s_add_output_share = circ->PutSharedOUTGate(sum);
#endif

	party->ExecCircuit();

	uint32_t out_bitlen_add, out_nvals;
	uint64_t *out_vals_add;

	add_out->get_clear_value_vec(&out_vals_add, &out_bitlen_add, &out_nvals);


#if ELEMENTARY_DEBUG
	uint64_t *in_x_share, *in_y_share, *out_share; 
	uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_add_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_add_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_add_output_share->get_clear_value_vec(&out_share, &out_bitlen_add, &out_nvals);	

	std::cout << "\n\nADD input x share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nADD input y share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nADD result share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nADD results: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " << *(double*) &(out_vals_add[i]) << std::endl;
		// std::cout << "\n RESULT[" << i << "]" << " = " << out_vals_add[i] << std::endl;
	}
#endif

	double op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n FP ADD, \t total time: " << op_time  << "ms" << std::endl;

	// uint64_t test = 4624252750237611852;
	// double test_double = *(double*) &test;
	// std::cout << "test double " << test_double  << std::endl;
	
	party->Reset();

//------ FP Mul gate ---------------
	// SIMD input gates
	ain = circ->PutSIMDINGate(nvals, avals, bitlen, SERVER);
	bin = circ->PutSIMDINGate(nvals, bvals, bitlen, CLIENT);

	// 32 bit input gate (non SIMD)
	//share* asqrtin = circ->PutINGate(afloatptr, 32, SERVER);

	share* mul = circ->PutFPGate(ain, bin, MUL, bitlen, nvals, no_status);
	share* mul_out = circ->PutOUTGate(mul, ALL);

#if ELEMENTARY_DEBUG 
	share *s_mul_input_x_share = circ->PutSharedOUTGate(ain);
	share *s_mul_input_y_share = circ->PutSharedOUTGate(bin);
	share *s_mul_output_share = circ->PutSharedOUTGate(mul);
#endif

	party->ExecCircuit();

	uint32_t out_bitlen_mul, out_mul_nvals;
	uint64_t *out_vals_mul;

	mul_out->get_clear_value_vec(&out_vals_mul, &out_bitlen_mul, &out_mul_nvals);

#if ELEMENTARY_DEBUG
	// uint64_t *in_x_share, *in_y_share, *out_share; 
	// uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_add_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_add_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_add_output_share->get_clear_value_vec(&out_share, &out_bitlen_mul, &out_mul_nvals);	

	std::cout << "\n\nMUL input x share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nMUL input y share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nMUL result share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nMUL results: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " << *(double*) &(out_vals_mul[i]) << std::endl;
		// std::cout << "\n RESULT[" << i << "]" << " = " << out_vals_add[i] << std::endl;
	}

	free(in_x_share);
	free(in_y_share);
	free(out_share);
#endif

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n FP MUL, \t total time: " << op_time  << "ms" << std::endl;
	party->Reset();


//------ FP CMP gate ---------------
	// SIMD input gates
	ain = circ->PutSIMDINGate(nvals, avals, bitlen, SERVER);
	bin = circ->PutSIMDINGate(nvals, bvals, bitlen, CLIENT);

	// 32 bit input gate (non SIMD)
	//share* asqrtin = circ->PutINGate(afloatptr, 32, SERVER);

	share* cmp = circ->PutFPGate(ain, bin, CMP, bitlen, nvals);
	share* cmp_out = circ->PutOUTGate(cmp, ALL);

#if ELEMENTARY_DEBUG 
	share *s_cmp_input_x_share = circ->PutSharedOUTGate(ain);
	share *s_cmp_input_y_share = circ->PutSharedOUTGate(bin);
	share *s_cmp_output_share = circ->PutSharedOUTGate(cmp);
#endif

	party->ExecCircuit();

	uint32_t out_bitlen_cmp, out_cmp_nvals;
	uint64_t *out_vals_cmp;

	cmp_out->get_clear_value_vec(&out_vals_cmp, &out_bitlen_cmp, &out_cmp_nvals);

#if ELEMENTARY_DEBUG
	// uint64_t *in_x_share, *in_y_share, *out_share; 
	// uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_cmp_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_cmp_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_cmp_output_share->get_clear_value_vec(&out_share, &out_bitlen_cmp, &out_cmp_nvals);	

	std::cout << "\n\nCMP input x share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nCMP input y share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nCMP result share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nCMP results: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " << out_vals_cmp[i] << std::endl;
		// std::cout << "\n RESULT[" << i << "]" << " = " << out_vals_add[i] << std::endl;
	}

	// free(in_x_share);
	// free(in_y_share);
	// free(out_share);
#endif

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n FP CMP, \t total time: " << op_time  << "ms" << std::endl;

	party->Reset();


//------ FP DIV gate ---------------
	// SIMD input gates
	ain = circ->PutSIMDINGate(nvals, avals, bitlen, SERVER);
	bin = circ->PutSIMDINGate(nvals, bvals, bitlen, CLIENT);

	// 32 bit input gate (non SIMD)
	//share* asqrtin = circ->PutINGate(afloatptr, 32, SERVER);

	share* div = circ->PutFPGate(ain, bin, DIV, bitlen, nvals);
	share* div_out = circ->PutOUTGate(div, ALL);

#if ELEMENTARY_DEBUG 
	share *s_div_input_x_share = circ->PutSharedOUTGate(ain);
	share *s_div_input_y_share = circ->PutSharedOUTGate(bin);
	share *s_div_output_share = circ->PutSharedOUTGate(div);
#endif

	party->ExecCircuit();

	uint32_t out_bitlen_div, out_div_nvals;
	uint64_t *out_vals_div;

	div_out->get_clear_value_vec(&out_vals_div, &out_bitlen_div, &out_div_nvals);

#if ELEMENTARY_DEBUG
	// uint64_t *in_x_share, *in_y_share, *out_share; 
	// uint32_t in_x_bitlen, in_y_bitlen, in_x_nvals, in_y_nvals; 
	s_div_input_x_share->get_clear_value_vec(&in_x_share , &in_x_bitlen , &in_x_nvals);	
	s_div_input_y_share->get_clear_value_vec(&in_y_share , &in_y_bitlen , &in_y_nvals);
	s_div_output_share->get_clear_value_vec(&out_share, &out_bitlen_div, &out_div_nvals);	

	std::cout << "\n\nDIV input x share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n xvals_share[" << i << "]" << " = " <<in_x_share[i] << std::endl;
	}

	std::cout << "\n\nDIV input y share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n yvals_share[" << i << "]" << " = " <<in_y_share[i] << std::endl;
	}

	std::cout << "\n\nDIV result share: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n Result_share[" << i << "]" << " = " <<out_share[i] << std::endl;
	}

	std::cout << "\n\nDIV results: " << std::endl;
	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "\n RESULT[" << i << "]" << " = " << *(double*) &(out_vals_div[i]) << std::endl;
		// std::cout << "\n RESULT[" << i << "]" << " = " << out_vals_add[i] << std::endl;
	}

	free(in_x_share);
	free(in_y_share);
	free(out_share);
#endif


	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n FP DIV, \t total time: " << op_time  << "ms" << std::endl;


	// // FP addition gate
	// share* sum = circ->PutFPGate(ain, bin, ADD, bitlen, nvals, no_status);

	// // 32-bit FP addition gate (bitlen, nvals, no_status are omitted)
	// //share* sqrt_share = circ->PutFPGate(asqrtin, SQRT);
	
	// share* cmp = circ->PutFPGate(ain, bin, CMP, bitlen, nvals);

	// // output gate
	// share* add_out = circ->PutOUTGate(sum, ALL);
	// // share* sqrt_out = circ->PutOUTGate(sqrt_share, ALL);
	// share* cmp_out = circ->PutOUTGate(cmp, ALL);

	// // run SMPC
	// party->ExecCircuit();

	// // retrieve plain text output
	// uint32_t out_bitlen_add, out_bitlen_cmp, out_nvals;
	// uint64_t *out_vals_add, *out_vals_cmp;

	// add_out->get_clear_value_vec(&out_vals_add, &out_bitlen_add, &out_nvals);
	// cmp_out->get_clear_value_vec(&out_vals_cmp, &out_bitlen_cmp, &out_nvals);

	// // print every output
	// for (uint32_t i = 0; i < nvals; i++) {

	// 	// dereference output value as double without casting the content
	// 	double val = *((double*) &out_vals_add[i]);

	// 	std::cout << "ADD RES: " << val << " = " << *(double*) &avals[i] << " + " << *(double*) &bvals[i] << " | nv: " << out_nvals
	// 	<< " bitlen: " << out_bitlen_add << std::endl;

	// 	std::cout << "CMP RES: " << out_vals_cmp[i] << " = " << *(double*) &avals[i] << " > " << *(double*) &bvals[i] << " | nv: " << out_nvals
	// 	<< " bitlen: " << out_bitlen_cmp << std::endl;
	// }

	// uint32_t *sqrt_out_vals = (uint32_t*) sqrt_out->get_clear_value_ptr();

	// float val = *((float*) sqrt_out_vals);

	// std::cout << "SQRT RES: " << val << " = " << sqrt(afloat) << std::endl;
}


int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 1, nvals = 4, secparam = 128, nthreads = 1;

	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	uint32_t test_bit = 0;
	double fpa = 0, fpb = 0;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
		&port, &test_op, &test_bit, &fpa, &fpb);

	std::cout << std::fixed << std::setprecision(3);
	std::cout << "double input values: " << fpa << " ; " << fpb << std::endl;

	seclvl seclvl = get_sec_lvl(secparam);


	test_verilog_add64_SIMD(role, address, port, seclvl, nvals, nthreads, mt_alg, S_BOOL, fpa, fpb);

	return 0;
}
