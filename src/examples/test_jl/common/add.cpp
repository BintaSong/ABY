/**
 \file 		millionaire_prob.cpp
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
 \brief		Implementation of the millionaire problem using ABY Framework.
 */

#include "add.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"

int32_t add_test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {

	/**
		Step 1: Create the ABYParty object which defines the basis of all the
		 	 	operations which are happening.	Operations performed are on the
		 	 	basis of the role played by this object.
	*/
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg);


	/**
		Step 2: Get to know all the sharing types available in the program.
		S_BOOL = 0, 
		S_YAO = 1, 
		S_ARITH = 2, 
		S_YAO_REV= 3, 
		S_SPLUT = 4,
		S_LAST = 5
	*/

	std::vector<Sharing*>& sharings = party->GetSharings();

	/**
		Step 3: Create the circuit object on the basis of the sharing type
				being inputed.
				--get concrete sharing from sharings vector by sharing type
	*/
	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();


	/**
		Step 4: Creating the share objects - s_a, s_b which
				is used as input to the computation function. Also s_out
				which stores the output.
	*/

	// share *s_a, *s_b, *s_out;

	// /**
	// 	Step 5: Initialize a and b with random values.
	// 			Both parties use the same seed, to be able to verify the
	// 			result. In a real example each party would only supply
	// 			one input value.

	// 			a and b are initialized with fixed values.
	// */
	// uint32_t a_int = 30;
    // uint32_t b_int = 40;
	// uint32_t output;

	// /**
	// 	Step 6: Copy the randomly generated money into the respective
	// 			share objects using the circuit object method PutINGate()
	// 			for my inputs and PutDummyINGate() for the other parties input.
	// 			Also mention who is sharing the object.
	// */
	// //s_a = circ->PutINGate(a, bitlen, CLIENT);
	// //s_b = circ->PutINGate(b, bitlen, SERVER);
	// if(role == SERVER) {
	// 	s_a = circ->PutDummyINGate(bitlen);
	// 	s_b = circ->PutINGate(b_int, bitlen, SERVER);
	// } else { //role == CLIENT
	// 	s_a = circ->PutINGate(a_int, bitlen, CLIENT);
	// 	s_b = circ->PutDummyINGate(bitlen);
	// }

	// /**
	// 	Step 7: Call the build method for building the circuit for the
	// 			problem by passing the shared objects and circuit object.
	// 			Don't forget to type cast the circuit object to type of share
	// */

	// s_out = BuildADDCircuit(s_a, s_b,
	// 		(BooleanCircuit*) circ);

	// /**
	// 	Step 8: Modify the output receiver based on the role played by
	// 			the server and the client. This step writes the output to the
	// 			shared output object based on the role.
	// */
	// s_out = circ->PutOUTGate(s_out, ALL);

	// /**
	// 	Step 9: Executing the circuit using the ABYParty object evaluate the
	// 			problem.
	// */
	// party->ExecCircuit();

	// /**
	// 	Step 10:Type casting the value to 32 bit unsigned integer for output.
	// */
	// output = s_out->get_clear_value<uint32_t>();

	// std::cout << "Testing ADD in " << get_sharing_name(sharing)
	// 			<< " sharing: " << std::endl;
	// std::cout << "\na is :\t" << a_int;
	// std::cout << "\nb is :\t" << b_int;
	// std::cout << "\nCircuit Result:\t" << output;
	// std::cout << "\nVerify Result: \t" << a_int + b_int
	// 			<< "\n";
	// return 0;




	// uint32_t a_int = 300;
    // uint32_t b_int = 400;

    // share* s_a;
    // share* s_b;
    // share* s_c;
    // // Input
    // if(role == SERVER){
    //     s_a = circ->PutINGate(a_int, bitlen, SERVER);
    //     s_b = circ->PutDummyINGate(bitlen);
	// 	//std::cout << "s_a output in server: " << std::endl;
	// 	//std::cout << "s_a output in server: " << s_a->get_clear_value<uint32_t>()<< std::endl;
	// 	//std::cout << "s_b output in server: " << s_b->get_clear_value<uint32_t>()<< std::endl;
	// }
    // else if(role == CLIENT){
    //     s_a = circ->PutDummyINGate(bitlen);
    //     s_b = circ->PutINGate(b_int, bitlen, CLIENT);
	// 	//std::cout << "s_a output in client: " << std::endl;
	// 	//std::cout << "s_a output in client: " << s_a->get_clear_value<uint32_t>()<< std::endl;
	// 	//std::cout << "s_b output in client: " << s_b->get_clear_value<uint32_t>()<< std::endl;
    // }
	// //std::cout << role << "executes before s_c" << std::endl;
    // s_c = circ->PutADDGate(s_a, s_b);
    // //std::cout << role << "executes s_c" << std::endl;
	// share* out = circ->PutSharedOUTGate(s_c);
	// //std::cout << role << "executes after s_c" << std::endl;
    // // Execute and get shared output
    // party->ExecCircuit();
	// //std::cout << role << "executes after party" << std::endl;
    // uint32_t c_int_shared = out->get_clear_value<uint32_t>();
    // std::cout << (role == SERVER?"server: ":"client: ") << c_int_shared << std::endl; // here output the shared value.
    // party->Reset(); // Reset after getting the output value
	
	// //std::cout << "test1" << std::endl;
    
	// // Put shared value as input
    // out = circ->PutSharedINGate(c_int_shared, bitlen);
    // out = circ->PutOUTGate(out, ALL);
	
	// //std::cout << "test2" << std::endl;
    
	// // Execute agagin and get the reconstructed result
    // party->ExecCircuit();
	// //std::cout << "test3" << std::endl;
    // uint32_t c_int = out->get_clear_value<uint32_t>();
	// //std::cout << "test4" << std::endl;
    // std::cout << "Result: " << c_int << std::endl; // here output the reconstructed value 7, the result of 3+4.
    // party->Reset();

	// delete party;
	// return 0;



	// //ox(892592254) xor ox(892592834) = ox(700)
	// uint32_t a_int = 892592254;
    // uint32_t b_int = 892592834;

    // share* out;
    // // Input
    // if(role == SERVER){
    //     out = circ->PutSharedINGate(a_int, bitlen);
	// }
    // else if(role == CLIENT){ 
    //     out = circ->PutSharedINGate(b_int, bitlen);
	// }
	// // Put shared value as input
    // out = circ->PutOUTGate(out, ALL);
	
	// //std::cout << "test2" << std::endl;
    
	// // Execute agagin and get the reconstructed result
    // party->ExecCircuit();
	// //std::cout << "test3" << std::endl;
    // uint32_t c_int = out->get_clear_value<uint32_t>();
	// //std::cout << "test4" << std::endl;
    // std::cout << "Result: " << c_int << std::endl; // here output the reconstructed value 7, the result of 3+4.
    // party->Reset();

	// delete party;
	// return 0;





	// uint32_t a_int = 3;
    // uint32_t b_int = 4;

    // share* s_a;
    // share* s_b;
    // share* s_c;
	// share* out;

    // // // Input
    // // if(role == SERVER){
    // //     s_a = circ->PutINGate(a_int, bitlen, SERVER);
    // //     s_b = circ->PutDummyINGate(bitlen);
	// // }
    // // else if(role == CLIENT){
    // //     s_a = circ->PutDummyINGate(bitlen);
    // //     s_b = circ->PutINGate(b_int, bitlen, CLIENT);
    // // }
	// // share* s_a_out = circ->PutSharedOUTGate(s_a);
	// // // Execute and get shared output
	// // party->ExecCircuit();
	// // uint32_t a_int_shared = s_a_out->get_clear_value<uint32_t>();
    // // std::cout << (role == SERVER?"server: ":"client: ") << a_int_shared << std::endl; // here output the shared value.
    
    // // party->Reset(); // Reset after getting the output value
    
	// // Put shared value as input
    
    // out = circ->PutOUTGate(out, ALL);
	    
	// // Execute agagin and get the reconstructed result
    // party->ExecCircuit();
    // uint32_t c_int = out->get_clear_value<uint32_t>();
    // std::cout << "Result: " << c_int << std::endl; // here output the reconstructed value 7, the result of 3+4.
    // party->Reset();

	// delete party;
	// return 0;


	// //Result: 7
	// //Result: 7
	// uint32_t a_int = 30;
    // uint32_t b_int = 40;
    // share* s_c;
	// share* out;
    
	// // Put shared value as input
	// if(role == SERVER){
	// 	out = circ->PutSharedINGate(a_int, bitlen);
	// }else if(role == CLIENT){
	// 	out = circ->PutSharedINGate(b_int, bitlen);
	// }
    
    // out = circ->PutOUTGate(out, ALL);
	// // Execute again and get the reconstructed result
    // party->ExecCircuit();
    // uint32_t c_int = out->get_clear_value<uint32_t>();
    // std::cout << "Result: " << c_int << std::endl; // here output the reconstructed value 7, the result of 3+4.
    // party->Reset();

	// delete party;
	// return 0;



	// //Result: 3
	// //Result: 4
	// uint32_t a_int = 3;
    // uint32_t b_int = 4;
    // share* s_c;
	// share* out;
    
	// // Put shared value as input
	// if(role == SERVER){
	// 	out = circ->PutSharedINGate(a_int, bitlen);
	// }else if(role == CLIENT){
	// 	out = circ->PutSharedINGate(b_int, bitlen);
	// }
    
    // //out = circ->PutOUTGate(out, ALL);
	// out = circ->PutSharedOUTGate(out);  
	// // Execute again and get the reconstructed result
    // party->ExecCircuit();
    // uint32_t c_int = out->get_clear_value<uint32_t>();
    // std::cout << "Result: " << c_int << std::endl; // here output the reconstructed value 7, the result of 3+4.
    // party->Reset();

	// delete party;
	// return 0;

	// std::cout <<"test" <<std::endl;
	// //Result: 3
	// //Result: 4
	// uint32_t a0_int = 3;
	// uint32_t a1_int = 2;//a = a1 - a0, b = b1 - b0
    // uint32_t b0_int = 2;
    // uint32_t b1_int = 4;
    // share* s_a;
	// share* s_b;
	// share* outa;
	// share* outb;
	// share* out;
    
	// // Put shared value as input
	// if(role == SERVER){
	// 	outa = circ->PutSharedINGate(a0_int, bitlen);
	// 	outb = circ->PutSharedINGate(b0_int, bitlen);
	// }else if(role == CLIENT){
	// 	outa = circ->PutSharedINGate(a1_int, bitlen);
	// 	outb = circ->PutSharedINGate(b1_int, bitlen);
	// }
	// std::cout <<"test2" <<std::endl;
	// out = circ->PutGTGate(outa, outb);
	// std::cout <<"test3" <<std::endl;

	// out = circ->PutOUTGate(out, ALL); 
	// std::cout <<"test4" <<std::endl; 
	// // Execute again and get the reconstructed result
    // party->ExecCircuit();
	// std::cout <<"test5" <<std::endl;

    // uint32_t c_out = out->get_clear_value<uint32_t>();
	// std::cout << "c_out is " << c_out << ", Circuit Result:\t" << (c_out ? ALICE : BOB) << std::endl;
    // party->Reset();

	// delete party;
	// return 0;


	//working on shared data
	// uint32_t a0_int = 31;
    // uint32_t a1_int = 40;
	// uint32_t b0_int = 30;
    // uint32_t b1_int = 40;

    // share* s_a;
    // share* s_b;
    // share* out;

    // // Input
    // if(role == SERVER){
    //     s_a = circ->PutSharedINGate(a0_int, bitlen);
	// 	s_b = circ->PutSharedINGate(b0_int, bitlen);
	// }
    // else if(role == CLIENT){
    //     s_a = circ->PutSharedINGate(a1_int, bitlen);
	// 	s_b = circ->PutSharedINGate(b1_int, bitlen);
	// }

	// if(role == SERVER){
    //     s_a = circ->PutSharedINGate(a0_int, bitlen);
	// }
    // else if(role == CLIENT){
    //     s_a = circ->PutSharedINGate(a1_int, bitlen);
	// }
	// s_a = circ->PutOUTGate(s_a, ALL);
	// // Execute and get shared output
	// party->ExecCircuit();
	// uint32_t a_int_shared = s_a->get_clear_value<uint32_t>();
    // std::cout << (role == SERVER?"server: ":"client: ") << a_int_shared << std::endl; // here output the shared value.
    // party->Reset(); // Reset after getting the output value
	// //Input


    // if(role == SERVER){
    //     //s_a = circ->PutSharedINGate(a0_int, bitlen);
	// 	s_b = circ->PutSharedINGate(b0_int, bitlen);
	// }
    // else if(role == CLIENT){
    //     //s_a = circ->PutSharedINGate(a1_int, bitlen);
	// 	s_b = circ->PutSharedINGate(b1_int, bitlen);
	// }


	// s_b = circ->PutOUTGate(s_b, ALL);
	// // Execute and get shared output
	// party->ExecCircuit();
	// uint32_t b_int_shared = s_b->get_clear_value<uint32_t>();
    // std::cout << (role == SERVER?"server: ":"client: ") << b_int_shared << std::endl; // here output the shared value.
    
    //party->Reset(); // Reset after getting the output value

	// out = circ->PutGTGate(s_a, s_b);

	// out = circ->PutSharedOUTGate(out);
	// // Execute again and get the reconstructed result
    // party->ExecCircuit();

    // uint32_t c_out = out->get_clear_value<uint32_t>();
    // std::cout << (role == SERVER?"server: ":"client: ") << c_out << std::endl; // here output the shared value.
	// //std::cout << "c_out is " << c_out << ", Circuit Result:\t" << (c_out ? ALICE : BOB) << std::endl;
    // party->Reset();

	// delete party;
	// return 0;



	//comparison
	uint32_t a0_int = 29; // 011101
    uint32_t a1_int = 42; // 101010
	uint32_t b0_int = 30; // 011110
    uint32_t b1_int = 40; // 101000
    share* s_a;
    share* s_b;
    share* out;

    // Input
    if(role == SERVER){
        s_a = circ->PutSharedINGate(a0_int, bitlen);
		s_b = circ->PutSharedINGate(b0_int, bitlen);
	}
    else if(role == CLIENT){
        s_a = circ->PutSharedINGate(a1_int, bitlen);
		s_b = circ->PutSharedINGate(b1_int, bitlen);
	}
	out = circ->PutGTGate(s_a, s_b);
	// out = circ->PutSharedOUTGate(out);
	// Execute again and get the reconstructed result
    party->ExecCircuit();
    uint32_t c_out = out->get_clear_value<uint32_t>();
    std::cout << (role == SERVER?"server: ":"client: ") << c_out << std::endl; // here output the shared value.
	//std::cout << "c_out is " << c_out << ", Circuit Result:\t" << (c_out ? ALICE : BOB) << std::endl;
    party->Reset();

	// //multiplexer
	// uint32_t a0_int = 1;
    // uint32_t a1_int = 2;
	// uint32_t b0_int = 3;
    // uint32_t b1_int = 4;

	// uint32_t sel0_int = 1;
    // uint32_t sel1_int = 1;
    // share* a;
    // share* b;
	// share* sel;
    // share* out;

    // // Input
    // if(role == SERVER){
    //     a = circ->PutSharedINGate(a0_int, bitlen);
	// 	b = circ->PutSharedINGate(b0_int, bitlen);
	// 	sel = circ->PutSharedINGate(sel0_int, bitlen);
	// }
    // else if(role == CLIENT){
    //     a = circ->PutSharedINGate(a1_int, bitlen);
	// 	b = circ->PutSharedINGate(b1_int, bitlen);
	// 	sel = circ->PutSharedINGate(sel1_int, bitlen);
	// }
	// out = circ->PutMUXGate(a, b, sel);
	// out = circ->PutSharedOUTGate(out);
	// // Execute again and get the reconstructed result
    // party->ExecCircuit();
    // uint32_t c_out = out->get_clear_value<uint32_t>();
    // std::cout << (role == SERVER?"server: ":"client: ") << c_out << std::endl; // here output the shared value.
	// //std::cout << "c_out is " << c_out << ", Circuit Result:\t" << (c_out ? ALICE : BOB) << std::endl;
    // party->Reset();

	delete party;
 	return 0;
}

share* BuildMillionCircuit(share *s_alice, share *s_bob,
		BooleanCircuit *bc) {

	share* out;

	/** Calling the greater than equal function in the Boolean circuit class.*/
	out = bc->PutGTGate(s_alice, s_bob);

	return out;
}


share* BuildADDCircuit(share *s_alice, share *s_bob,
		BooleanCircuit *bc) {

	share* out;

	/** Calling the greater than equal function in the Boolean circuit class.*/
	out = bc->PutADDGate(s_alice, s_bob);

	return out;
}