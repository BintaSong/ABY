/**
 \file 		elementary.cpp
 \author 	sreeram.sadasivam@cased.de
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

int32_t test_elementary_circuit(e_role role, const std::string& address, uint32_t port, seclvl seclvl,
		uint32_t numbers, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg) {

	/**
	 Step 1: Create the ABYParty object which defines the basis of all the
	 operations which are happening.	Operations performed are on the
	 basis of the role played by this object.
	 */
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg);

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
	srand(time(NULL));

	for (i = 0; i < numbers; i++) {

		x = rand() % (2 << 6);
		y = rand() % (2 << 6);

		//v_sum += x + y;

		xvals[i] = x;
		yvals[i] = y;

		std::cout << "\n xvals[i] : " << xvals[i] << std::endl;

	}

	uint32_t out_bitlen = 32, out_nvals = numbers, *out_vals;
	double op_time; 


// //-------------------test float number----------
// float s1 = 1.0;
// uint32_t s2 = 1 << 3;

// for (uint32_t i = 0; i < 4; i++) {
// 	float tmp = (float) xvals[i] / 8;
// 	std::cout << "\n tmp : " << tmp << std::endl;
// 	// s1 *= tmp ; 
// 	s2 = s2 * xvals[i] >> 3;
// }
// // 100000010100101001011010
// // 111001001000110
// // 101110
// std::cout << "\n s2 : " << s2 << std::endl;

// //for (uint32_t i = 0; i < 4; i += 1) { 
// 	//float tmp = (float) xvals[i] / 128;
// 	uint32_t tmp1 = xvals[0] * xvals[1] >> 3;
// 	uint32_t tmp2 = xvals[2] * xvals[3] >> 3;
// 	uint32_t tmp3 = tmp1 * tmp2 >> 3;

// 	std::cout << "\n s2 : " << tmp3 << std::endl;

// 	// s1 *= tmp ; //}
// uint32_t real = xvals[0] * xvals[1] * xvals[2] * xvals[3] / (64*8); 
// std::cout << "\n real : " << real << std::endl;


//-------------------test add-------------------
	s_x_vec = ac->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_y_vec = ac->PutSIMDINGate(numbers, yvals.data(), 32, CLIENT);
	s_out = BuildAddCircuit(s_x_vec, s_y_vec, numbers, ac);
	s_out = ac->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	
	s_out -> get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;
	// for (int i = 0; i < 10; i++) {
	// 	std::cout << "\n add out_vals: " << out_vals[i] << std::endl;
	// }

	 op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n ADD \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();

//-------------------test mul -------------------
	s_x_vec = ac->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_y_vec = ac->PutSIMDINGate(numbers, yvals.data(), 32, CLIENT);
	s_out = BuildMulCircuit(s_x_vec, s_y_vec, numbers, ac);
	s_out = ac->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	//uint32_t out_bitlen, out_nvals, *out_vals;
	s_out -> get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;
	// for (int i = 0; i < 10; i++) {
	// 	std::cout << "\n mul out_vals: " << out_vals[i] << std::endl;
	// }

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n Mul \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();


//-------------------test CMP -------------------
	s_x_vec = bc->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_y_vec = bc->PutSIMDINGate(numbers, yvals.data(), 32, CLIENT);
	s_out = BuildCmpCircuit(s_x_vec, s_y_vec, numbers, bc);
	s_out = bc->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	//uint32_t out_bitlen, out_nvals, *out_vals;
	s_out -> get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;
	// for (int i = 0; i < 10; i++) {
	// 	std::cout << "\n cmp out_vals: " << out_vals[i] << std::endl;
	// }

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n CMP \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();


	share **share_ptr_vec;  
	share_ptr_vec = (share**) malloc(sizeof(share*) * numbers); 
//------------------- test Max -------------------
	for (uint32_t i = 0; i < numbers; i++) {
		share_ptr_vec[i] = bc->PutINGate(xvals[i], 32, SERVER);
	}

	s_out = bc->PutMaxGate(share_ptr_vec, numbers);
	s_out = bc->PutOUTGate(s_out, ALL); 
	party->ExecCircuit();

	uint32_t max = s_out ->get_clear_value<uint32_t>();
	// std::cout << "\n Max = " << max << std::endl;

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n MAX \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();

//------------------- test Min -------------------
	for (uint32_t i = 0; i < numbers; i++) {
		share_ptr_vec[i] = bc->PutINGate(xvals[i], 32, SERVER);
	}

	s_out = bc->PutMinGate(share_ptr_vec, numbers);
	s_out = bc->PutOUTGate(s_out, ALL); 
	party->ExecCircuit();

	uint32_t min = s_out ->get_clear_value<uint32_t>();
	// std::cout << "\n Min = " << min << std::endl;

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n MIN \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset(); 


//------------------- test Var ----------------
	share *s_x2_vec, *s_sum, *s2_sum; 
	s_x_vec = ac->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_x2_vec = BuildMulCircuit(s_x_vec, s_x_vec, numbers, ac); 

	s_x_vec = ac->PutSplitterGate(s_x_vec);
	s_x2_vec = ac->PutSplitterGate(s_x2_vec);

	for (i = 1; i < numbers; i++) {
		s_x_vec->set_wire_id(0, ac->PutADDGate(s_x_vec->get_wire_id(0), s_x_vec->get_wire_id(i)));
		s_x2_vec->set_wire_id(0, ac->PutADDGate(s_x2_vec->get_wire_id(0), s_x2_vec->get_wire_id(i)));
	}
	s_x_vec->set_bitlength(1);
	s_x2_vec->set_bitlength(1);
	s_sum = ac->PutMULGate(s_x_vec, s_x_vec);
	
	s_sum = ac->PutOUTGate(s_sum, ALL);
	s2_sum = ac->PutOUTGate(s_x2_vec, ALL);
	
	party->ExecCircuit(); 
	
	uint32_t sum = s_sum->get_clear_value<uint32_t>();
	uint32_t sum2 = s2_sum->get_clear_value<uint32_t>();
	double var = 1.0 * sum2 / numbers - 1.0 * sum / (numbers * numbers);
	std::cout << "\n var = " << var << std::endl;

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n VAR \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();



//------------------- test odd-even Sort ----------------

// void odd_even_sort(int arr[], int len) {
// 	int odd_even, i;
// 	int temp;
// 	int sorted = 0;
// 	while (!sorted) {
// 		sorted = 1;
// 		for (odd_even = 0; odd_even < 2; odd_even++)
// 			for (i = odd_even; i < len - 1; i += 2)
// 				if (arr[i] > arr[i + 1]) {
// 					temp = arr[i];
// 					arr[i] = arr[i + 1];
// 					arr[i + 1] = temp;
// 					sorted = 0;
// 				}
// 	}
// }
	uint32_t sorted = 0;

	share* s_cmp, *s_sorted, *s_one, *s_zero; 

	s_one = bc->PutINGate((uint32_t)1, 32, SERVER);
	s_zero = bc->PutINGate((uint32_t)0, 32, SERVER);

	for (uint32_t i = 0; i < numbers; i++) {
		share_ptr_vec[i] = bc->PutINGate(xvals[i], 32, SERVER);
	}

	uint32_t odd_even = 0;

	while(!sorted) {
		s_sorted = s_one;
		for (odd_even = 0; odd_even < 2; odd_even++) {
			for (uint32_t i = odd_even; i < numbers-1; i++) {
				s_cmp = bc->PutGTGate(share_ptr_vec[i], share_ptr_vec[i+1]);
				share *tmp1, *tmp2;
				tmp1 = bc->PutMUXGate(share_ptr_vec[i+1], share_ptr_vec[i], s_cmp);
				tmp2 = bc->PutMUXGate(share_ptr_vec[i], share_ptr_vec[i+1], s_cmp);
				share_ptr_vec[i] = tmp1;
				share_ptr_vec[i+1] = tmp2;

				s_sorted = bc->PutMUXGate(s_zero, s_sorted, s_cmp);
			}
		}
		

	} 

	party->Reset();



	delete s_x_vec;
	delete s_y_vec;
	delete party;

	return 0;
}

/*
 Constructs the multiplication circuit. num multiplications and num additions.
 */
share* BuildMulCircuit(share *s_x, share *s_y, uint32_t numbers, ArithmeticCircuit *ac) {
	uint32_t i;

	// pairwise multiplication of all input values
	s_x = ac->PutMULGate(s_x, s_y);

	// split SIMD gate to separate wires (size many)
	// s_x = ac->PutSplitterGate(s_x);

	return s_x;
}


/*
 Constructs the add circuit.
 */
share* BuildAddCircuit(share *s_x, share *s_y, uint32_t numbers, ArithmeticCircuit *ac) {
	uint32_t i;

	// pairwise multiplication of all input values
	s_x = ac->PutADDGate(s_x, s_y);


	// split SIMD gate to separate wires (size
	return s_x;
}

/*
 Constructs the compare circuit.
 */
share* BuildCmpCircuit(share *s_x, share *s_y, uint32_t numbers, BooleanCircuit *bc) {
	share *out;
	// pairwise comparison of all input values
	out = bc->PutGTGate(s_x, s_y);

	// split SIMD gate to separate wires (size many)
	// out = bc->PutSplitterGate(out);

	return out;
}

/*
 Constructs the Max circuit.
 */
share* BuildMaxCircuit(share *s_x, share *s_y, uint32_t numbers, ArithmeticCircuit *ac, BooleanCircuit *bc) {
	uint32_t i;
	share *out; 
	// pairwise multiplication of all input values

	// split SIMD gate to separate wires (size many)
	// out = ac->PutSplitterGate(s_x);


	return out;
}
