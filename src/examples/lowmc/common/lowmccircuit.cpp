/**
 \file 		lowmccircuit.cpp
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
            GNU Lesser General Public License for moroffset_Constante details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Prototypical benchmark implementation of LowMCCiruit. Attention: Does not yield correct result!
 */
#include "lowmccircuit.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/crypto/crypto.h>

static uint32_t m_nRndCtr;
static uint32_t* m_tGrayCode;
static uint32_t* m_tGrayCodeIncrement;
static uint32_t m_nZeroGate;

static uint32_t offset_LMatric;
static uint32_t offset_InvLMatric;
static uint32_t offset_Constant;
static uint32_t offset_KMatric;


void print_matrices( const LowMCParams* param ) {
    std::cout << "LowMC matrices and constants" << std::endl;
    std::cout << "============================" << std::endl;
    std::cout << "Block size: " << param->blocksize << std::endl;
    std::cout << "Key size: " << param->keysize << std::endl;
    std::cout << "Rounds: " << param->nrounds << std::endl;
    std::cout << std::endl;

    std::cout << "Linear layer matrices" << std::endl;
    std::cout << "---------------------" << std::endl;
    for (unsigned r = 0; r < param->nrounds ; ++r) {
        std::cout << "Linear layer " << r << ":" << std::endl;
		for ( unsigned i = 0; i < param->blocksize; i++) {
			std::cout << "[";
			for (unsigned j = 0; j < param->blocksize; ++j) {
				std::cout << (int) m_vRandomBits.GetBit(offset_LMatric + r * param->blocksize * param->blocksize + i *  param->blocksize + j);
				if (j != param->blocksize - 1) {
					std::cout << ", ";
				}
			}
			std::cout << "]" << std::endl;
		}
        std::cout << "Linear layer " << r << ", " << param->blocksize << " * " << param->blocksize << std::endl;
    }

    std::cout << "Round constants" << std::endl;
    std::cout << "---------------------" << std::endl;
    for (unsigned r = 0; r < param->nrounds; ++r) {
        std::cout << "Round constant " << r << ":" << std::endl;
        std::cout << "[";
        for (unsigned i = 0; i < param->blocksize; ++i) {
            std::cout << (int) m_vRandomBits.GetBit(offset_Constant + r * param->blocksize + i);
            if (i != param->blocksize - 1) {
                std::cout << ", ";
            }
        }
        std::cout << "]" << std::endl;
        std::cout << std::endl;
        std::cout << "Round constant " << r << ", " << param->blocksize << " * 1"<< std::endl;
    }
    
    std::cout << "Round key matrices" << std::endl;
    std::cout << "---------------------" << std::endl;
    for (unsigned r = 0; r <= param->nrounds; ++r) {
        std::cout << "Round key matrix " << r << ":" << std::endl;
        for (unsigned i = 0; i < param->blocksize; ++i) {
            std::cout << "[";
            for (unsigned j = 0; j < param->keysize; ++j) {
                std::cout << (int) m_vRandomBits.GetBit(offset_KMatric + r * param->blocksize * param->keysize + i * param->keysize + j);
                if (j != param->keysize - 1) {
                    std::cout << ", ";
                }
            }
            std::cout << "]" << std::endl;
        }
        if (r != param->nrounds) {
            std::cout << std::endl;
        }
        std::cout << "Round key matrix " << r << ", " << param->blocksize << " * "<< param->keysize << std::endl;
    }
}

void load_lowmc_state(const LowMCParams* param) {

	offset_LMatric = 0;
	offset_InvLMatric = param->blocksize * param->blocksize * param->nrounds;
	offset_Constant = offset_InvLMatric + param->blocksize * param->blocksize * param->nrounds;
	offset_KMatric = offset_Constant +  param->blocksize * param->nrounds;

	//------------read lowmc state locally------------
	std::string parameters = std::to_string(param->nsboxes) + "_" + std::to_string(param->blocksize) + "_" + std::to_string(param->keysize) + "_" + std::to_string(param->nrounds);
	std::string local_state_file =  "lowmc_" + parameters + "_.state";

	std::ifstream file_in(local_state_file.c_str()); // 打开状态保存文本
	if (!file_in.is_open()) {
		throw std::runtime_error(local_state_file + ": unable to read the lowmc state file");
	}
 	std::stringstream rand_buf;
    rand_buf << file_in.rdbuf();
	file_in.close();
	
	std::string local_state_str = rand_buf.str();
	size_t state_size = 2 * param->blocksize * param->blocksize * param->nrounds /* lin and invlin*/
					  + param->nrounds * param->blocksize /* counstant */
					  + (param->nrounds + 1) * param->blocksize * param->keysize;

	m_vRandomBits.Create(state_size);
	assert(state_size == local_state_str.size());
	for(int i = 0; i < state_size; i++) {
		m_vRandomBits.SetBit(i, local_state_str[i]);
	}
}

void keyschedule(CBitVector& raw_key, CBitVector& extend_key, const LowMCParams* param) {
	//------------generate round keys----------------
	for(int r = 0; r <= param->nrounds; r++) {
		//std::cout << "Round: " << r <<std::endl;
		for(int i = 0; i < param->blocksize; i++) {
			uint8_t tmp = 0;
			for(uint8_t j = 0; j < param->keysize; j++) {
				// NOTE: raw_key is encode as little-end
				uint8_t m = j / 8, n = j % 8;
				uint8_t little_end_j = 8 * m + 7 - n;

				tmp += m_vRandomBits.GetBit(offset_KMatric + r * param->blocksize * param->keysize + i * param->keysize + j) & raw_key.GetBit(little_end_j);
				tmp = tmp % 2;
			}
			// NOTE: key is encode as little-end due to ABY requirement !
			//uint8_t m = i / 8, n = i % 8, little_end_i = 8 * m + 7 - i;
			extend_key.SetBit(r * param->blocksize + ((i / 8) * 8 + 7 - (i % 8)), tmp);
		}
	}
}

void test_lowmc_circuit_shared_input(e_role role, uint32_t nvals, crypto* crypt, e_sharing sharing, ABYParty *party, std::vector<Sharing *> &sharings, Circuit *circ, LowMCParams* para,
                BYTE* key, BYTE* inputShare, BYTE* outputShare, e_role key_inputter) {
	
	uint32_t exp_key_bitlen = para->blocksize * (para->nrounds+1);


	// we want load_lowmc_state() and keyschedule() only be done once, to make lowmc_circuit_shared_input() focus on main task 
	load_lowmc_state(para);

	CBitVector raw_key(para->keysize), extend_key(exp_key_bitlen);
	if (role == key_inputter) {
		raw_key.SetBytes(key, 0, para->keysize/8); 
		keyschedule(raw_key, extend_key, para);

		// std::cout << "lowmc extend key: "<< std::endl;
        // for (int j = 0; j < para->keysize; j++) {
        //     std::cout << std::to_string( extend_key.GetBit(j));
        // }
        // std::cout <<std::endl;
	}

	lowmc_circuit_shared_input(role, nvals, crypt, sharing, party, sharings, circ, para, extend_key, inputShare, outputShare, key_inputter); 
}

void lowmc_circuit_shared_input(e_role role, uint32_t nvals, crypto* crypt, e_sharing sharing, ABYParty *party, std::vector<Sharing *> &sharings, Circuit *circ, LowMCParams* para,
                CBitVector& extend_key, BYTE* inputShare, BYTE* outputShare, e_role key_inputter) {
	
	uint32_t exp_key_bitlen = para->blocksize * (para->nrounds+1), zero_gate;
	
	//Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
	//Circuit build routine works for Boolean circuits only
	assert(circ->GetCircuitType() == C_BOOLEAN);

	share *s_in, *s_key, *s_ciphertext, *s_out_debug, *s_in_debug;
	// s_in = circ->PutSIMDINGate(nvals, input.GetArr(), para->blocksize, CLIENT);
	s_in = circ->PutSharedSIMDINGate(nvals, inputShare, para->blocksize);

	// s_in = circ->PutSharedINGate(inputShare, para->blocksize);
	// s_in = circ->PutRepeaterGate(nvals, s_in);
	//circ->PutPrintValueGate(s_in, "s_in");
	s_key = circ->PutINGate(extend_key.GetArr(), exp_key_bitlen, key_inputter);
	s_key = circ->PutRepeaterGate(nvals, s_key);
	
	zero_gate = circ->PutConstantGate(0, nvals);

	//zero_gate = circ->PutConstantGate(0, nvals);

	s_ciphertext = BuildLowMCCircuit(role, s_in, s_key, (BooleanCircuit*) circ, para, zero_gate, crypt);

	s_out_debug = circ->PutOUTGate(s_ciphertext, ALL);
	s_ciphertext = circ->PutSharedOUTGate(s_ciphertext);
	//s_ciphertext = circ->PutOUTGate(s_ciphertext, ALL);
	s_in_debug = circ->PutOUTGate(s_in, ALL);
	
	
	party->ExecCircuit();

	uint8_t* output = s_ciphertext->get_clear_value_ptr();
	uint8_t* out_debug = s_out_debug->get_clear_value_ptr();
	uint8_t* in_debug = s_in_debug->get_clear_value_ptr();
	
	for (int i = 0; i < nvals; i++) {
		std::cout << "\nLOWMC_INPUT_DEBUG: "<< i << std::endl;
		for (int j = ceil_divide(para->blocksize, 8) - 1; j >= 0; j--) {
			std::cout << std::bitset<8>(in_debug[i * para->blocksize/8 + j]);
		}
		std::cout <<std::endl;
	}

	
	for (int i = 0; i < nvals; i++) {
		std::cout << "\nLOWMC_OUTPUT_DEBUG: "<< i << std::endl;
		for (int j = ceil_divide(para->blocksize, 8) - 1; j >= 0; j--) {
			std::cout << std::bitset<8>(out_debug[i * para->blocksize/8 + j]);
		}
		std::cout <<std::endl;
	}
    

	// CBitVector out;
	// out.AttachBuf(output, (uint64_t) ceil_divide(para->blocksize, 8) * nvals);
	// //std::cout << param->blocksize << " .. " << out.GetSize() <<std::endl; 

	// std::cout<< "two party lowMC ciphertext size: " << out.GetSize()*8 <<std::endl; 
	// for (int i = 0; i < out.GetSize()*8; i++) {
	// 	//std::cout<< std::hex <<  std::setw(2) << std::setfill('0') << (int) out.GetByte(i);
	// 	std::cout<< (int) out.GetBit(i);
	// }
	// std::cout<<std::endl;

	memcpy(outputShare, output, (uint64_t) ceil_divide(para->blocksize, 8) * nvals);
	
	// std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) << std::endl;

	// for (int j = 0; j < ceil_divide(para->blocksize, 8) * nvals; j++) {
	// 	std::cout << std::bitset<8>(outputShare[j]);
	// }
	// std::cout<<std::endl;

	free(output);

}



//sboxes (m), key-length (k), statesize (n), data (d), rounds (r)
int32_t test_lowmc_circuit(e_role role, const std::string& address, uint16_t port, uint32_t nvals, uint32_t nthreads,
		e_mt_gen_alg mt_alg, e_sharing sharing, uint32_t statesize, uint32_t keysize,
		uint32_t sboxes, uint32_t rounds, uint32_t maxnumgates, crypto* crypt) {
	
	LowMCParams param = { sboxes, keysize, statesize, keysize == 80 ? 64 : (uint32_t) 128, rounds };

	load_lowmc_state(&param);

	return test_lowmc_circuit(role, address, port, nvals, nthreads, mt_alg, sharing, &param, maxnumgates, crypt);
}

int32_t test_lowmc_circuit(e_role role, const std::string& address, uint16_t port, uint32_t nvals, uint32_t nthreads,
		e_mt_gen_alg mt_alg, e_sharing sharing, LowMCParams* param, uint32_t reservegates, crypto* crypt) {

	uint32_t bitlen = 32, ctr = 0, exp_key_bitlen = param->blocksize * (param->nrounds+1), zero_gate;

	ABYParty* party;
	if(reservegates > 0)
		party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg, reservegates);
	else
		party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg);

	std::vector<Sharing*>& sharings = party->GetSharings();

	//------------prepare input and key------------
	CBitVector input, key;
	input.Create(param->blocksize * nvals);
	BYTE test_input[param->blocksize] = {0x02, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
	                                     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	input.SetBytes(test_input, 0, param->blocksize / 8);

#if LOWMC_DEBUG
	std::cout<< "two party plaintext size: " << input.GetSize()*8 <<std::endl;
	for (int i = 0; i < input.GetSize()*8; i++) {
		//std::cout<< std::hex <<  std::setw(2) << std::setfill('0') << (int) out.GetByte(i);
		std::cout<< (int) input.GetBit(i);
	}
	std::cout<<std::endl;
#endif
	// test_key, raw_key are encoded as little-end
	BYTE test_key[param->keysize/8] = {0x04, 0x03, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	
	CBitVector raw_key(param->keysize), extend_key(exp_key_bitlen);
	raw_key.SetBytes(test_key, 0, param->keysize/8); 
	keyschedule(raw_key, extend_key, param);

#if LOWMC_DEBUG
	std::cout<< "two party raw key size: " << key.GetSize()*8 <<std::endl;
	
	for (int i = 0; i < raw_key.GetSize()*8; i++) {
		std::cout<< (int) raw_key.GetBit(i);
	}
	std::cout<< std::endl;
#endif

#if LOWMC_DEBUG	
	std::cout<< "two party extend key size: " << key.GetSize()*8 <<std::endl;
	assert( exp_key_bitlen ==  key.GetSize()*8);
	for (int r = 0; r <= param->nrounds; r++) {
		std::cout<< "extend key for round: " << r <<std::endl;
		for (int i = 0; i < param->blocksize; i++){
			std::cout<< (int) key.GetBit(r * param->blocksize + i);
		}
		std::cout<<std::endl;
	}
	std::cout<<std::endl;
#endif 

	uint8_t* output;

	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
	//Circuit build routine works for Boolean circuits only
	assert(circ->GetCircuitType() == C_BOOLEAN);

	share *s_in, *s_key, *s_ciphertext;
	s_in = circ->PutSIMDINGate(nvals, input.GetArr(), param->blocksize, CLIENT);
	s_key = circ->PutINGate(extend_key.GetArr(), exp_key_bitlen, SERVER);
	s_key = circ->PutRepeaterGate(nvals, s_key);
	zero_gate = circ->PutConstantGate(0, nvals);

	s_ciphertext = BuildLowMCCircuit(role, s_in, s_key, (BooleanCircuit*) circ, param, zero_gate, crypt);

	s_ciphertext = circ->PutOUTGate(s_ciphertext, ALL);

	party->ExecCircuit();

	output = s_ciphertext->get_clear_value_ptr();

	CBitVector out;
	out.AttachBuf(output, (uint64_t) ceil_divide(param->blocksize, 8) * nvals);
	//std::cout << param->blocksize << " .. " << out.GetSize() <<std::endl; 

	std::cout<< "two party lowMC ciphertext size: " << out.GetSize()*8 <<std::endl; 
	for (int i = 0; i < out.GetSize()*8; i++) {
		//std::cout<< std::hex <<  std::setw(2) << std::setfill('0') << (int) out.GetByte(i);
		std::cout<< (int) out.GetBit(i);
	}
	std::cout<<std::endl;

	std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) << std::endl;
	//print_matrices(param);
	return 1;
}

share* BuildLowMCCircuit(e_role role, share* val, share* key, BooleanCircuit* circ, LowMCParams* param, uint32_t zerogate, crypto* crypt) {
	uint32_t round, byte, i, j, k;
	m_nRndCtr = 0;
	uint32_t nsboxes = param->nsboxes;
	uint32_t statesize = param->blocksize;
	uint32_t nrounds = param->nrounds;
	uint32_t keysize = param->keysize;
	std::vector<uint32_t> state(statesize);

	m_nZeroGate = zerogate;

	//Build the GrayCode for the optimal window-size
	m_tGrayCode = BuildGrayCode(statesize);
	m_tGrayCodeIncrement = BuildGrayCodeIncrement(statesize);

	//copy the input to the current state
	for (i = 0; i < statesize; i++) {
		state[i] = val->get_wire_id(i);
		// std::cout<< "statesize: "<< statesize << ", wire id: " << (int ) state[i] << " \n";
	}

	uint32_t counter = 0;
	//LowMCAddRoundKey(state, key->get_wires(), statesize, 0, circ); //ARK
	LowMCXORMultipliedKey(state, key->get_wires(), statesize, 0, circ);
	//return new boolshare(state, circ);
	for (round = 1; round <= nrounds; round++) {
		counter += 1;
		//substitution via 3-bit SBoxes
		LowMCPutSBoxLayer(state, nsboxes, statesize, circ);

		//multiply state with GF2Matrix
		counter += 1;
		LowMCMultiplyState(state, statesize, round, circ);//Naive version of the state multiplication
		//FourRussiansMatrixMult(state, statesize, circ);//4 Russians version of the state multiplication
		//LowMCMultiplyStateCallback(state, statesize, circ); //use callbacks to perform the multiplication in plaintext
		//if (round == 1 && counter == 2) break;


		counter += 1;
		//XOR constants
		LowMCXORConstants(state, statesize, round, circ);

		counter += 1;
		//XOR with multiplied key
		LowMCXORMultipliedKey(state, key->get_wires(), statesize, round, circ);
//if (round == 10 && counter == 4) break;

		counter = 0;
	}

	free(m_tGrayCode);
	free(m_tGrayCodeIncrement);

#if PRINT_PERFORMANCE_STATS
	std::cout << "Total Number of Boolean Gates: " << circ->GetNumGates() << std::endl;
#endif

	return new boolshare(state, circ);
}

// void LowMCAddRoundKey(std::vector<uint32_t>& val, std::vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
// 	for (uint32_t i = 0; i < lowmcstatesize; i++) {
// 		val[i] = circ->PutXORGate(val[i], key[i+(1+round) * lowmcstatesize]);
// 	}
// }

void LowMCAddRoundKey(std::vector<uint32_t>& val, std::vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		val[i] = circ->PutXORGate(val[i], key[i+round * lowmcstatesize]);
	}
}

//Multiply the state using a linear matrix
void LowMCMultiplyState(std::vector<uint32_t>& state, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
	std::vector<uint32_t> tmpstate(lowmcstatesize);
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		// tmpstate[i] = 0; FIXME: WRONG USAGE, 0 is the wire id of input's LSB ! 
		tmpstate[i] = m_nZeroGate;
		for (uint32_t j = 0; j < lowmcstatesize; j++) {
			// compute current position
			uint32_t current_pos = offset_LMatric + (round - 1) * lowmcstatesize * lowmcstatesize + i * lowmcstatesize + j; 
			if (m_vRandomBits.GetBit(current_pos)) {
				tmpstate[i] = circ->PutXORGate(tmpstate[i], state[j]);
			}
		}
	}
	state = tmpstate;
}
// //Multiply the state using a linear matrix
// void LowMCMultiplyState(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
// 	std::vector<uint32_t> tmpstate(lowmcstatesize);
// 	for (uint32_t i = 0; i < lowmcstatesize; i++) {
// 		tmpstate[i] = 0;
// 		for (uint32_t j = 0; j < lowmcstatesize; j++, m_nRndCtr++) {
// 			if (m_vRandomBits.GetBit(m_nRndCtr)) {
// 				tmpstate[i] = circ->PutXORGate(tmpstate[i], state[j]);
// 			}
// 		}
// 	}
// }

//XOR constants on the state
void LowMCXORConstants(std::vector<uint32_t>& state, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		uint32_t current_pos = offset_Constant + (round - 1) * lowmcstatesize + i;
		if (m_vRandomBits.GetBit(current_pos)) {
			state[i] = circ->PutINVGate(state[i]);
		}
	}
}

// //XOR constants on the state
// void LowMCXORConstants(std::vector<uint32_t>& state, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
// 	for (uint32_t i = 0; i < lowmcstatesize; i++, m_nRndCtr++) {
// 		if (m_vRandomBits.GetBit(m_nRndCtr)) {
// 			state[i] = circ->PutINVGate(state[i]);
// 		}
// 	}

// }

//Multiply the key with a 192x192 matrix and XOR the result on the state.
void LowMCXORMultipliedKey(std::vector<uint32_t>& state, std::vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
	uint32_t tmp;
	/*for(uint32_t i = 0; i < MPCC_STATE_SIZE; i++) {
	 tmp = 0;
	 for(uint32_t j = 0; j < MPCC_STATE_SIZE; j++, m_nRndCtr++) {
	 if(m_vRandomBits.GetBit(m_nRndCtr)) {
	 tmp = PutXORGate(tmp, key[j]);
	 }
	 }
	 state[i] = PutXORGate(state[i], tmp);
	 }*/
	//Assume outsourced key-schedule
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		state[i] = circ->PutXORGate(state[i], key[i+round * lowmcstatesize]);
	}

}

//Put a layer of 3-bit LowMC SBoxes
void LowMCPutSBoxLayer(std::vector<uint32_t>& input, uint32_t nsboxes, uint32_t statesize, BooleanCircuit* circ) {
	for (uint32_t i = 0; i < nsboxes * 3; i += 3) {
		// std::cout<< "before: " << input[i] <<std::endl;
		LowMCPutSBox(input[i+2], input[i + 1], input[i], circ);
		// std::cout<< "after: " << input[i] <<std::endl;
	}
}

// void LowMCPutSBoxLayer(std::vector<uint32_t>& input, uint32_t nsboxes, uint32_t statesize, BooleanCircuit* circ) {
// 	assert(statesize >= 3*nsboxes);
// 	uint32_t pos;
// 	for (uint32_t i = 1; i <= nsboxes; i++) {
// 		pos = statesize - 3*i;
// 		std::cout<< pos <<std::endl;
// 		LowMCPutSBox(input[pos], input[pos+1], input[pos+2], circ);
// 	}
// }

//Put a 3-bit LowMC SBoxes
void LowMCPutSBox(uint32_t& o1, uint32_t& o2, uint32_t& o3, BooleanCircuit* circ) {
	uint32_t i1 = o1;
	uint32_t i2 = o2;
	uint32_t i3 = o3;

	uint32_t ni1 = circ->PutINVGate(i1);
	uint32_t ni2 = circ->PutINVGate(i2);
	uint32_t ni3 = circ->PutINVGate(i3);

	//D = B * C + A
	//o1 = circ->PutANDGate(i2, i3);
	o1 = circ->PutXORGate(circ->PutANDGate(i2, i3), i1);
	//o1 = ni1;
	// //E = A * (NOT C) + B
	o2 = circ->PutXORGate(circ->PutANDGate(i1, ni3), i2);
	//o2 = ni2;
	// //F = (NOT ((NOT B) * (NOT A))) + C
	 o3 = circ->PutXORGate(circ->PutINVGate(circ->PutANDGate(ni2, ni1)), i3);
	//o3 = ni3;
}

void FourRussiansMatrixMult(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
	//round to nearest square for optimal window size
	uint32_t wsize = floor_log2(lowmcstatesize) - 2;

	//will only work if the statesize is a multiple of the window size
	uint32_t* lutptr;
	uint32_t* lut = (uint32_t*) malloc(sizeof(uint32_t) * (1 << wsize));
	uint32_t i, j, bitctr, tmp = 0;

	lut[0] = m_nZeroGate;	//circ->PutConstantGate(0, 1);

	std::vector<uint32_t> tmpstate(ceil_divide(lowmcstatesize, wsize) * wsize, lut[0]);
	//pad the state to a multiple of the window size and fill with zeros
	std::vector<uint32_t> state_pad(ceil_divide(lowmcstatesize, wsize) * wsize, lut[0]);
	for (i = 0; i < lowmcstatesize; i++)
		state_pad[i] = state[i];

	for (i = 0, bitctr = 0; i < ceil_divide(lowmcstatesize, wsize); i++) { //for each column-window
		for (j = 1; j < (1 << wsize); j++) {
			lut[m_tGrayCode[j]] = circ->PutXORGate(lut[m_tGrayCode[j - 1]], state_pad[i * wsize + m_tGrayCodeIncrement[j - 1]]);
		}

		for (j = 0; j < lowmcstatesize; j++, bitctr += wsize) {
			m_vRandomBits.GetBits((BYTE*) &tmp, bitctr, wsize);
			tmpstate[i] = circ->PutXORGate(tmpstate[j], lut[tmp]);
		}
	}

	for (i = 0; i < lowmcstatesize; i++)
		state[i] = tmpstate[i];

	free(lut);
}

void LowMCMultiplyStateCallback(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
	std::vector<uint32_t> tmpstate(lowmcstatesize);
	UGATE_T*** fourrussiansmat;

	circ->PutCallbackGate(state, 0, &CallbackBuild4RMatrixAndMultiply, (void*) fourrussiansmat, 1);
	for (uint32_t i = 1; i < lowmcstatesize-1; i++) {
		matmul* mulinfos = (matmul*) malloc(sizeof(matmul));
		mulinfos->column = i;
		//mulinfos->matrix = (UGATE_T) fourrussiansmat;

		tmpstate[i] = circ->PutCallbackGate(state, 0, &CallbackMultiplication, (void*) mulinfos, 1);
	}
	circ->PutCallbackGate(state, 0, &CallbackMultiplyAndDestroy4RMatrix, (void*) fourrussiansmat, 1);


	for (uint32_t i = 0; i < lowmcstatesize; i++)
		state[i] = tmpstate[i];
}

void CallbackMultiplication(GATE* gate, void* matinfos) {
	std::cout << "Performing multiplication" << std::endl;
	for(uint32_t i = 0; i < gate->ingates.ningates; i++) {

	}
	//alternatively, check if i == 0 and then call CallbackBuild4RMatrix(gate, matinfos.matrix); and check if i == statesize-1 and delete matrix
	free(matinfos);
}

void CallbackBuild4RMatrixAndMultiply(GATE* gate, void* mat) {
	//for(uint32_t i = 0; i < )
	//TODO
	std::cout << "Building 4 Russians matrix" << std::endl;
}

void CallbackMultiplyAndDestroy4RMatrix(GATE* gate, void* matrix) {
	//TODO
}

uint32_t* BuildGrayCode(uint32_t length) {
	uint32_t* gray_code = (uint32_t*) malloc(sizeof(uint32_t) * length);
	for(uint32_t i = 0; i < length; ++i) {
		gray_code[i] = i ^ (i >> 1);
	}
	return gray_code;
}

uint32_t* BuildGrayCodeIncrement(uint32_t length) {
	uint32_t* gray_code_increment = (uint32_t*) malloc(sizeof(uint32_t) * length);
	for(uint32_t i = 0; i < length; ++i) {
		gray_code_increment[i] = 0;
	}
	uint32_t length_inc = 2;
	while(length_inc < length) {
		uint32_t length_count = length_inc - 1;
		while(length_count <= length) {
			(gray_code_increment[length_count])++;
			length_count += length_inc;
		}
		length_inc <<= 1; 
	}
	return gray_code_increment;
}

bool is_file(const std::string& path)
{
    struct stat sb;
    
    if (stat(path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode))
    {
        return true;
    }
    return false;
}


// lowmcCircuit::lowmcCircuit(const LowMCParams* param) {
// 	load_lowmc_state(param);
	
// }