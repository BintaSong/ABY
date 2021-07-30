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

	for (i = 0; i < numbers; i++) {

		x = rand() % (2 << 16);
		y = rand() % (2 << 16);

		//v_sum += x + y;

		xvals[i] = x;
		yvals[i] = y;

	}

	uint32_t out_bitlen = 32, out_nvals = numbers, *out_vals;
	double op_time; 


//-------------------test OddEvenMergeSort-------------------
    // OddEvenMergeSort(xvals.data(), 0, numbers); 
	// for (uint32_t i = 0; i < 10; i++) {
	// 	std::cout << "\n element " << i << " : " << xvals[i] << std::endl;
	// }



//-------------------test add-------------------
	s_x_vec = ac->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_y_vec = ac->PutSIMDINGate(numbers, yvals.data(), 32, CLIENT);
	s_out = BuildAddCircuit(s_x_vec, s_y_vec, numbers, ac);
	s_out = ac->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	
	s_out->get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;	

	// check correctness
	std::cout<< "\nCheking correctness of addtion... \t";
	for (uint32_t i = 0; i < numbers; i++) {
		assert(out_vals[i] == (xvals[i]+yvals[i]));
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n ADD \t Total time: " << op_time  << "ms" << std::endl;

	

	party->Reset();
	delete out_vals;



//-------------------test mul -------------------
	s_x_vec = ac->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_y_vec = ac->PutSIMDINGate(numbers, yvals.data(), 32, CLIENT);
	s_out = BuildMulCircuit(s_x_vec, s_y_vec, numbers, ac);
	s_out = ac->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	s_out->get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;

	// check correctness
	std::cout<< "\nCheking correctness of multiplication...\t";
	for (uint32_t i = 0; i < numbers; i++) {
		assert(out_vals[i] == (xvals[i]*yvals[i]));
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;


	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n Mul \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();
	delete out_vals;


//-------------------test CMP -------------------
	s_x_vec = bc->PutSIMDINGate(numbers, xvals.data(), 32, SERVER);
	s_y_vec = bc->PutSIMDINGate(numbers, yvals.data(), 32, CLIENT);
	s_out = BuildCmpCircuit(s_x_vec, s_y_vec, numbers, bc);
	s_out = bc->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();

	s_out->get_clear_value_vec(&out_vals , &out_bitlen , &out_nvals) ;

	// check correctness
	std::cout<< "\nCheking correctness of compare...\t "<< out_bitlen << ", " << out_nvals;
	for (uint32_t i = 0; i < numbers; i++) {
		//std::cout<< out_vals[i]  << " " << xvals[i] << " " << yvals[i] << " " <<  (xvals[i]>yvals[i]) <<std::endl;
		assert(out_vals[i] == (xvals[i]>yvals[i]));
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;



	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n CMP \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();
	delete out_vals;



//------------------- test Max -------------------
	share **share_ptr_vec;  
	share_ptr_vec = (share**) malloc(sizeof(share*) * numbers); 
	for (uint32_t i = 0; i < numbers; i++) {
		share_ptr_vec[i] = bc->PutINGate(xvals[i], 32, SERVER);
	}

	s_out = bc->PutMaxGate(share_ptr_vec, numbers);
	s_out = bc->PutOUTGate(s_out, ALL); 
	party->ExecCircuit();

	uint32_t max = s_out ->get_clear_value<uint32_t>();
	
	// check correctness
	std::cout<< "\nCheking correctness of MAX...\t";
	for (uint32_t i = 0; i < numbers; i++) {
		
		// assert(out_vals[i] == (xvals[i]>yvals[i]));
	}
	std::cout<< "\033[32m\033[1m"  << "PASSED."  << "\033[0m" <<std::endl;



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



	for (uint32_t i = 0; i < numbers; i++) {
		share_ptr_vec[i] = bc->PutINGate(xvals[i], 32, SERVER);
	}

	BuildOddEvenMergeSort(share_ptr_vec, 0, numbers, bc);  

	// BuildBubbleSort(share_ptr_vec, numbers, bc);

	for (uint32_t i = 0; i < numbers; i++) {
		share_ptr_vec[i] = bc->PutOUTGate(share_ptr_vec[i], ALL);
	}

	party->ExecCircuit(); 
	
	for (uint32_t i = 0; i < 10; i++) {
		uint32_t element = share_ptr_vec[i]->get_clear_value<uint32_t>();
		std::cout << "\n element " << i << " : " << element << std::endl;
	}

	op_time = party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
	std::cout << "\n Sort \t Total time: " << op_time  << "ms" << std::endl;

	party->Reset();


	delete share_ptr_vec; 

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

// void bubbleSort(int arr[], int n)
// {
//     int i, j;
//     for (i = 0; i < n-1; i++)    
     
//     // Last i elements are already in place
//     for (j = 0; j < n-i-1; j++)
//         if (arr[j] > arr[j+1])
//             swap(&arr[j], &arr[j+1]);
// }

void BuildBubbleSort(share **s_vec, uint32_t length, BooleanCircuit* bc) {

	share *s_cmp, *s_big, *s_small; 
	for (uint32_t i = 0; i < length - 1; i++) {
		for (uint32_t j = 0; j < length - i - 1; j++) {
			s_cmp = bc->PutGTGate(s_vec[j], s_vec[j+1]);
			s_big = bc->PutMUXGate(s_vec[j], s_vec[j+1], s_cmp); 
			s_small = bc->PutMUXGate(s_vec[j+1], s_vec[j], s_cmp); 
			s_vec[j+1] = s_big;
			s_vec[j] = s_small;
		}
	}
}

void BuildEvenMerge(share **s_vec, uint32_t lo, uint32_t n, uint32_t r, BooleanCircuit* bc) {
	uint32_t m = r*2;
	if(m < n) {
		BuildEvenMerge(s_vec, lo, n, m, bc);
		BuildEvenMerge(s_vec, lo+r, n, m, bc); 
		share *s_cmp, *tmp1, *tmp2;
		for (uint32_t i = lo + r; i + r < lo+n; i += m) {
			// compare and exchange (i, i+1) 
			s_cmp = bc -> PutGTGate(s_vec[i], s_vec[i+r]); 
			tmp1 = bc->PutMUXGate(s_vec[i+r], s_vec[i], s_cmp); 
			tmp2 = bc->PutMUXGate(s_vec[i], s_vec[i+r], s_cmp); 
			s_vec[i] = tmp1;
			s_vec[i+r] = tmp2;
		}
	}
	else { // compare and exchange (lo, lo+r)
		share *s_cmp = bc -> PutGTGate(s_vec[lo], s_vec[lo+r]); 
		share *tmp1, *tmp2;
		tmp1 = bc->PutMUXGate(s_vec[lo+r], s_vec[lo], s_cmp); 
		tmp2 = bc->PutMUXGate(s_vec[lo], s_vec[lo+r], s_cmp); 
		s_vec[lo] = tmp1;
		s_vec[lo+r] = tmp2;
	}
}


void BuildOddEvenMergeSort(share **s_vec, uint32_t lo, uint32_t n, BooleanCircuit* bc) {
	if (n > 1) {
		uint32_t m = n / 2;
		BuildOddEvenMergeSort(s_vec, lo, m, bc);
		BuildOddEvenMergeSort(s_vec, lo+m, m, bc);
		BuildEvenMerge(s_vec, lo, n, 1, bc);
	}
}

void EvenMerge(uint32_t *vec, uint32_t lo, uint32_t n, uint32_t r) {
	uint32_t m = r*2;
	if(m < n) {
		EvenMerge(vec, lo, n, m);
		EvenMerge(vec, lo+r, n, m); 
		for (uint32_t i = lo + r; i + r < lo+n; i += m) {
			// compare and exchange (i, i+1) 
			if (vec[i] > vec[i+r]) {
				uint32_t tmp = vec[i];
				vec[i] = vec[i+r];
				vec[i+r] = tmp; 
			}
		}
	}
	else { // compare and exchange (lo, lo+r)
		if (vec[lo] > vec[lo+r]) {
			uint32_t tmp = vec[lo]; 
			vec[lo] = vec[lo+r]; 
			vec[lo+r] = tmp; 
		}
	}
}
void OddEvenMergeSort(uint32_t *vec, uint32_t lo, uint32_t n) { 
	if (n > 1) {
		uint32_t m = n / 2;
		OddEvenMergeSort(vec, lo, m);
		OddEvenMergeSort(vec, lo+m, m);
		EvenMerge(vec, lo, n, 1);
	}
}