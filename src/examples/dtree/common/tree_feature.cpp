#include "tree_feature.h"
string fssResultFile1 = "../../src/examples/dtree/fss/ZeroOrOne0.txt";
string fssResultFile2 = "../../src/examples/dtree/fss/ZeroOrOne1.txt";

//keys of server
BYTE keys1[] = { 0x6E, 0x66, 0xAE, 0x0B,
        0xE7, 0x29, 0x41, 0xEB,
        0xA6, 0x53, 0x10, 0x21,
        0x13, 0x76, 0x08, 0x2E
    };
BYTE keys2[] = { 0xda, 0xdf, 0x11, 0xe7, 
        0x4d, 0x01, 0x4a, 0x62, 
        0xd7, 0x3c, 0xca, 0xdd, 
        0x95, 0x91, 0x44, 0x2a
    };
BYTE keys3[] = { 0x61, 0xD6, 0xAE, 0x8B,
        0xE7, 0x29, 0x41, 0xEB,
        0xAF, 0x5E, 0x90, 0x21,
        0x73, 0x76, 0x08, 0x2A
    };
//key of client
BYTE keyc4[] = { 0x21, 0xE6, 0xAE, 0x3B,
        0xE7, 0x29, 0x41, 0x0B,
        0xAC, 0x5E, 0xA0, 0x21,
        0x71, 0x46, 0x0D, 0x5A
    };

BYTE lowmc_server_key[] = {0x04, 0x03, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0
    };

BYTE lowmc_client_key[] = {0x04, 0x03, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0
    };


void get_tree_and_feature(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, string filename, uint64_t featureDim, uint64_t r, uint32_t depthHide, uint32_t nvals, [[maybe_unused]] bool verbose, bool use_vec_ands, bool expand_in_sfe, bool client_only){
	srand((unsigned int)time(NULL)); // real random
    DecTree tree;
	tree.read_from_file(filename);
    int totalNum = tree.num_dec_nodes + tree.num_of_leaves;
    uint64_t featureMax = pow(2, ceil(log(featureDim)/log(2)));
    
#ifdef DTREE_DEBUG
    cout << "tree.num_attributes in use " << tree.num_attributes << ", tree.featureDim in real " << featureDim << '\n';
    cout << "tree.depth " << tree.depth  << '\n';
	cout << "tree.num_dec_nodes " << tree.num_dec_nodes  << '\n';
    cout << "tree.num_of_leaves " << tree.num_of_leaves  << '\n';
    cout << "tree total nodes " << totalNum  << '\n';
#endif
    //----------------tree and feature reading----------------
    uint64_t node[5];


// you can choose to encrypt the decision tree either by aes or lowmc

#if DTREE_ENCRYPTED_BY_LOWMC
	vector<node_tuple_mz> encryptedTree = encrypt_tree(tree, node); // encrypt tree using lowMC
#else 
    vector<node_tuple_mz> encryptedTree = return_tree(tree, node);  // encrypt tree using AES
#endif

#ifdef DTREE_DEBUG
    for(int i = 0; i < 5; i++){
        cout << node[i] << endl;
    }
#endif

    /*
    //generating random attribute values of feature vector
    node_tuple_mz encryptedFeature = return_feature(featureDim, featureMax);
    */

    //for test....generating fixed attribute values of feature vector

#if DTREE_ENCRYPTED_BY_LOWMC 
    node_tuple_mz encryptedFeature = encrypt_fixed_feature(featureDim, featureMax);
#else
    node_tuple_mz encryptedFeature = return_fixed_feature(featureDim, featureMax);
#endif 
    //-----------Read Evaluation Result of FSS for feature----------------
    vector<int> zeroOrOneFt;
    FSSFeatureRead(role, fssResultFile1, fssResultFile2, zeroOrOneFt, featureMax, featureDim);


    //-----------Read Evaluation Result of FSS for tree----------------
    vector<int> zeroOrOneDt;
    FSSTreeRead(role, fssResultFile1, fssResultFile2, zeroOrOneDt, totalNum);

    //-----------initial root node-----------
    //a0-a4 should be randomly chosen in the future.
    uint64_t a0 = 123456, a1 = 678, a2 = 910, a3 = 5, a4 = 6;
    if(role == SERVER){
        node[0] = a0;
        node[1] = a1;
        node[2] = a2;
        node[3] = a3;
        node[4] = a4;
    }else if(role == CLIENT){
        node[0] = node[0] ^ a0;
        node[1] = node[1] ^ a1;
        node[2] = node[2] ^ a2;
        node[3] = node[3] ^ a3;
        node[4] = node[4] ^ a4;
    }
    

    // ---- ABY init --------
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();
    crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	Circuit *circ = sharings[sharing]->GetCircuitBuildRoutine();
    Circuit* ac = sharings[S_ARITH]->GetCircuitBuildRoutine();//for converting
    share* s_a;
    share* s_b;
    share* s_cmp; 
    share* s_c;
	share* out;
    
    #if DTREE_ENCRYPTED_BY_LOWMC
        // load lowmc parametres before used
        // FIXME: numofboxes, keysize, blocksize, keysize, rounds are defined in LowMC.h
        LowMCParams param = {numofboxes, keysize, blocksize, keysize == 80 ? 64 : (uint32_t) 128, rounds};
        load_lowmc_state(&param);

        uint32_t secparam = 128, exp_key_bitlen = blocksize * (rounds+1);

        CBitVector raw_server_key(keysize), raw_client_key(keysize), extend_server_key(exp_key_bitlen), extend_client_key(exp_key_bitlen);

        // uint64_t key;
        // memcpy(&key, lowmc_client_key, sizeof(uint64_t));
        // std::cout << "the key: " << key << std::endl; 

        if(role == SERVER) {
            raw_server_key.SetBytes(lowmc_server_key, 0, keysize/8);
            keyschedule(raw_server_key, extend_server_key, &param);
	    }
        else if(role == CLIENT) {
            raw_client_key.SetBytes(lowmc_client_key, 0, keysize/8);
            keyschedule(raw_client_key, extend_client_key, &param);
        }
    #endif

    for(int i = 0; i < tree.depth + depthHide; i++){
    // #ifdef DTREE_DEBUG
        std::cout << "\n*****************this is in depth " << i << "******************" << endl; 
    // #endif 
        //-----------Compute delta = r ^ node[3] by Mpc----------------
        s_a = circ->PutSharedINGate(r, bitlen);
        s_b = circ->PutSharedINGate(node[3], bitlen);

        out = circ->PutXORGate(s_a, s_b);
        out = circ->PutOUTGate(out, ALL);//public delta

        party->ExecCircuit();

        uint64_t delta = out->get_clear_value<uint64_t>();
    //#ifdef DTREE_DEBUG
        cout << (role == SERVER?"server feature delta: ":"client feature delta: ") << (int) delta << endl; // here output the shared value.
    //#endif
        party->Reset();
        

        //-----------Compute shared attribute value----------------
        mpz_class sharedAttri = 0;
        for (int i = 0; i < featureMax; i++) {
            sharedAttri = (*(encryptedFeature.plain.data() +(i^delta)) * zeroOrOneFt[i]) ^ sharedAttri;
            //cout << sharedAttri << endl;
        }
        std::cout << " Attribute share is: " << sharedAttri.get_str(2) << std::endl;

    #ifdef DTREE_DEBUG
        cout << "shared atrribute value from " << (role == SERVER?"server: ":"client: ") << " is " << sharedAttri << endl;
        //verify the correctness of shared attribute value
        // mpz_class a("254660458319129247083910018378620234586", 10);
        // mpz_class b("234615298901844452662224218719500917163", 10);
        // cout << "shared encrypted atrribute value is " << (a ^ b) << endl;
    #endif
    #if DTREE_DEBUG
        //----------reveal next index of attri for AES(should be removed in the future)-----------
        std::cout << ("before, node[3]: ") << node[3] << endl; // here output the value.
        out = circ->PutSharedINGate(node[3], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t nextAttriInd = out->get_clear_value<uint64_t>();
        party->Reset();
        std::cout << ("after, node[3]: ") << node[3] << endl; 
        std::cout << (role == SERVER?"server feature id: ":"client feature id: ") << nextAttriInd << endl; // here output the value.
    #endif
    #if DTREE_ENCRYPTED_BY_LOWMC
        // do two-party lowmc evaluation
        BYTE index_share[blocksize/8], lowmc_share[blocksize/8];
        memset(index_share, 0, blocksize/8);
        memcpy(index_share, node+3, sizeof(uint64_t)); // indeed, node[3]'s length is 8 bytes 
        
        std::cout << "\nindex_share: " << node[3] << std::endl;
            for (int i = 7 ; i >= 0; i--) {
               std::cout << std::bitset<8>(index_share[i]);
            }
        std::cout<<std::endl;

            // for (int i = 0 ; i < 8; i++) {
            //     for (int j = 0; j < 8; j++) {
            //         if (node[3] & (uint64_t)1 << (8*i+j)) std::cout<<1;
            //         else std::cout << 0;
            //     }
            // }
            // std::cout<<std::endl;
//load_lowmc_state(&param);
        lowmc_circuit_shared_input(role, 1, crypt, sharing, party, sharings, circ, &param, extend_client_key, index_share, lowmc_share, CLIENT);
       

        // std::cout << "\nlowmc extend key: "<< std::endl;
        // for (int j = 0; j < keysize; j++) {
        //     std::cout << std::to_string( extend_client_key.GetBit(j));
        // }
        // std::cout <<std::endl;

        std::cout << "\nlowmc_share: "<< std::endl;
        for (int j = ceil_divide(blocksize, 8) - 1; j >= 0; j--) {
            std::cout << std::bitset<8>(lowmc_share[j]);
        }
        std::cout <<std::endl;

        //std::cout << "lowmc" << std::endl;
        mpz_xor_mask(lowmc_share, blocksize, sharedAttri); // now sharedAttri is decrypted and shared between parties
        std::cout << " Decrypted attribute share is: " << sharedAttri.get_str(2) << std::endl;

        party->Reset();


        //std::cout << "lowmc" << std::endl;
    #else
        BYTE indShared[16];
        aes_circuit(role, nvals, sharing,  party, crypt, sharings, circ, node[3], indShared, keyc4, verbose, use_vec_ands, expand_in_sfe, client_only);
        party->Reset();
        aes_xor_class_plain(indShared, sharedAttri);// server and client do xor locally
    #endif

    #ifdef DTREE_DEBUG
        cout << "shared atrribute value from " << (role == SERVER?"server: ":"client: ") << " is " << sharedAttri << endl;
    #endif


    #ifdef DTREE_DEBUG//AES by server locally.
        //----------reveal next index of attri for AES(should be removed in the
        //future)-----------
        out = circ->PutSharedINGate(node[3], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t nextAttriInd = out->get_clear_value<uint64_t>();
        party->Reset();
        cout << (role == SERVER?"server: ":"client: ") << nextAttriInd << endl; // here output the value.

        //-------------AES descryption----------------
        //AES decryption, currently, we let the server decrypt the his part, and the client do nothing.
        if(role == SERVER){
            //6 should be shared
            prf_aes_128_decrypt_by_key_feature(nextAttriInd, sharedAttri);
        }
        cout << "shared atrribute value from " << (role == SERVER?"server: ":"client: ") << " is " << sharedAttri << endl;
    #endif

    uint64_t attri;
    #if DTREE_ENCRYPTED_BY_LOWMC 
    // std::cout << "lowmc1" << std::endl;    
    sharedAttri = sharedAttri % pow(2, 64); 
    std::cout << " Decrypted attribute mod 2^64 share is: " << sharedAttri.get_str(2) << std::endl; 
        attri = mpz2uint64(sharedAttri);


        BYTE tmp[8];
        memcpy(tmp, &attri, 8); 
        std::cout << "\nint attribute: "<< std::endl;
        for (int j = 8 - 1; j >= 0; j--) {
            std::cout << std::bitset<8>(tmp[j]);
        }
        std::cout <<std::endl;
    std::cout << "end attri" << std::endl;     

    #else
        //we deconcatenate 128bits to 64bits
        deconcatenate(sharedAttri, attri);
    #endif 
        //-----------Comparison a threshold and an attribute value by Mpc----------------
        //should be x[i] <= t, if true, go left, else, go right
        //that is t >= x[i], if true, go left, else, go right
        s_a = circ->PutSharedINGate(node[0], bitlen);
        s_b = circ->PutSharedINGate(attri, bitlen);
        s_cmp = circ->PutGTGate(s_a, s_b);

        s_a = circ->PutSharedINGate(node[1], bitlen);
        s_b = circ->PutSharedINGate(node[2], bitlen);
        //if s_cmp  = 1, s_a will be returned, otherwise, s_b is returned.
        out = circ->PutMUXGate(s_a, s_b, s_cmp);
        out = circ->PutSharedOUTGate(out);
    #ifdef DTREE_DEBUG
        cout << "\n**Running Multiplexer subprotocol..." << endl;
    #endif 
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t next = out->get_clear_value<uint64_t>();
        party->Reset();


        //-----------B2A for r and next, the result is also shared ini arith : for the convinience of fss result * tree node----------------
        s_a = circ->PutSharedINGate(r, bitlen);//2
        s_b = circ->PutSharedINGate(next, bitlen);//1
        s_a = ac->PutB2AGate(s_a);
        s_b = ac->PutB2AGate(s_b);
        s_c = ac->PutSUBGate(s_b, s_a);
        out = ac->PutOUTGate(s_c, ALL);
        // Execute again and get the reconstructed result
        party->ExecCircuit();
        //avoid negtive number by adding totalNum, because the offset should be positive
        uint64_t out_delta;
        if(out->get_clear_value<int64_t>() < 0){
            out_delta = out->get_clear_value<int64_t>() + totalNum;
        }else{
            out_delta = out->get_clear_value<uint64_t>();
        }
    #ifdef DTREE_DEBUG
        cout << "delta of tree" << (role == SERVER?"server: ":"client: ") << out_delta << std::endl; // here output the shared value.
    #endif
        party->Reset();


        //-----------Reading one of a tree node according to offset out_delta in
        //local----------------
    #if DTREE_ENCRYPTED_BY_LOWMC
        uint16_t n_simd_blocks = ceil_divide(5 * 64, blocksize); 
        mpz_class blocks_shares[n_simd_blocks] = {0};

        for(int i = 0; i < totalNum; i++) {
            for (int j = 0; j < n_simd_blocks; j++) {
                blocks_shares[j] ^= (*(encryptedTree[(i+out_delta)%totalNum].plain.data() + j) * zeroOrOneDt[i]); 
            }
        }

    #else
        mpz_class share1 = 0, share2 = 0, share3 = 0;
        for(int i = 0; i < totalNum; i++){
            share1 = (*(encryptedTree[(i+out_delta)%totalNum].plain.data()) * zeroOrOneDt[i]) ^ share1;
            share2 = (*(encryptedTree[(i+out_delta)%totalNum].plain.data() + 1) * zeroOrOneDt[i]) ^ share2;
            share3 = (*(encryptedTree[(i+out_delta)%totalNum].plain.data() + 2) * zeroOrOneDt[i]) ^ share3;
        }
    #endif 

    #if DTREE_ENCRYPTED_BY_LOWMC
        // use two-party lowmc for decryption 
        std::cout << "\nbegin lowmc tree shared decryption" << std::endl;
        BYTE simd_inputs[n_simd_blocks * blocksize / 8], simd_outputs[n_simd_blocks * blocksize / 8];
        memset(simd_inputs, 0, n_simd_blocks * blocksize / 8); //FIXME: must do this
        memset(simd_outputs, 0, n_simd_blocks * blocksize / 8);

        uint64_t simd_next_index[n_simd_blocks];

        std::cout << "\nnext : " << std::bitset<64>(next) << std::endl;
        for (uint64_t i = 0 ; i < n_simd_blocks; i++) {
            // set simd_next as [ next<<3+0, next<<3+1, next<<3+2,... ]
            simd_next_index[i] = role == SERVER ? (next << 3) + i: next << 3; // FIXME: next << 3 + i <==> next << (3+i) !!!
            memcpy(simd_inputs + i*(blocksize/8), simd_next_index + i, sizeof(uint64_t));
            
            std::cout << "\nsimd_inputs: "<< i << std::endl;

            //for (int i = 0; i < n_simd_blocks; i++)
                //for (int j = blocksize / 8 - 1; j >= 0; j--) {
                    std::cout << std::bitset<64>(simd_next_index[i]) << std::endl;
                //}
            //std::cout <<std::endl;
        }

        lowmc_circuit_shared_input(role, n_simd_blocks, crypt, sharing, party, sharings, circ, &param, extend_server_key, simd_inputs, simd_outputs, SERVER);

        std::cout << "\nsimd_outputs [0]: "<< std::endl;
        for (int j = ceil_divide(blocksize, 8) - 1; j >= 0; j--) {
            std::cout << std::bitset<8>(simd_outputs[j]);
        }
        std::cout <<std::endl;

        for (uint64_t i = 0 ; i < n_simd_blocks; i++) {
            mpz_xor_mask(simd_outputs + i * blocksize / 8, blocksize, blocks_shares[i]); 
            std::cout << " Decrypted block share : "<< i << " : " << blocks_shares[i].get_str(2) << std::endl; 
        }
        party->Reset();
    #else 
        BYTE nodeShared1[16];
        BYTE nodeShared2[16];
        BYTE nodeShared3[16];
        aes_circuit(role, nvals, sharing,  party, crypt, sharings, circ, next, nodeShared1, keys1, verbose, use_vec_ands, expand_in_sfe, client_only);
        party->Reset();
        aes_circuit(role, nvals, sharing,  party, crypt, sharings, circ, next, nodeShared2, keys2, verbose, use_vec_ands, expand_in_sfe, client_only);
        party->Reset();
        aes_circuit(role, nvals, sharing,  party, crypt, sharings, circ, next, nodeShared3, keys3, verbose, use_vec_ands, expand_in_sfe, client_only);
        party->Reset();
        aes_xor_class_plain(nodeShared1, share1);// server and client do xor locally
        aes_xor_class_plain(nodeShared2, share2);// server and client do xor locally
        aes_xor_class_plain(nodeShared3, share3);// server and client do xor locally
    #endif    

    #ifdef DTREE_DEBUG
        //----------reveal next index of tree node for AES(should be removed in the future)-----------
        out = circ->PutSharedINGate(next, bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t nextNodeInd = out->get_clear_value<uint64_t>();
    #ifdef DTREE_DEBUG
        cout << "The index of the next node is " << nextNodeInd << endl; // here output the shared value.
    #endif
        party->Reset();

        //-------------AES descryption of tree node----------------
        //AES decryption, currently, we let the server decrypt the his part, and the client do nothing.
        if(role == SERVER){
            //nextNodeInd in the middle should be shared
            prf_aes_128_decrypt_by_key(1, nextNodeInd, share1);
            prf_aes_128_decrypt_by_key(2, nextNodeInd, share2);
            prf_aes_128_decrypt_by_key(3, nextNodeInd, share3);
        }
    #endif

    #ifdef DTREE_DEBUG
        cout << "shared node from " << (role == SERVER?"server: ":"client: ") << " is \n" 
            << share1 << "\n"
            << share2 << "\n"
            << share3 << endl;
    #endif 

    #ifdef DTREE_DEBUG
        mpz_class ct3("237943597451638649168184169838402329861", 10);
        mpz_class dt3("293998737720940441927202041852477233338", 10);
        cout << "shared share1 is " << (ct3 ^ dt3) << endl;
    #endif 

    #if DTREE_ENCRYPTED_BY_LOWMC
        //parse lowmc blocks
        deconcatenate(blocks_shares, n_simd_blocks, node);
    #else 
        //we deconcatenate 128bits to two 64bits. From this, we can get shares of next node on plaintext
        deconcatenate(share1, node[0], node[1]);
        deconcatenate(share2, node[2], node[3]);
        deconcatenate(share3, node[4]);
    #endif

    // if (i == 1) break ;

    #ifdef DTREE_DEBUG
        out = circ->PutSharedINGate(node[0], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t node0 = out->get_clear_value<uint64_t>();
        cout << "node0 in " << (role == SERVER?"server: ":"client: ") << node0 << endl; 
        party->Reset();
    #endif
        
    #ifdef DTREE_DEBUG
        out = circ->PutSharedINGate(node[1], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t node1 = out->get_clear_value<uint64_t>();
        cout << "node1 in " << (role == SERVER?"server: ":"client: ") << node1 << endl;
        party->Reset(); 
    #endif 
        
    #ifdef DTREE_DEBUG
        out = circ->PutSharedINGate(node[2], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t node2 = out->get_clear_value<uint64_t>();
        cout << "node2 in " << (role == SERVER?"server: ":"client: ") << node2 << endl; 
        party->Reset();
    #endif 

    #ifdef DTREE_DEBUG
        out = circ->PutSharedINGate(node[3], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t node3 = out->get_clear_value<uint64_t>();
        cout << "node3 in " << (role == SERVER?"server: ":"client: ") << node3 << endl;
        party->Reset();
    #endif 

    #ifdef DTREE_DEBUG
        out = circ->PutSharedINGate(node[4], bitlen);
        out = circ->PutOUTGate(out, ALL);
        party->ExecCircuit();
        //output will be the shares of the index of next node
        uint64_t node4 = out->get_clear_value<uint64_t>();
        cout << "node4 in " << (role == SERVER?"server: ":"client: ") << node4 << endl;
        party->Reset();
    #endif 
    } //end for

#ifdef DTREE_DEBUG
    cout << "------------Shared classification result is " << node[4] << endl;
#endif 
    //----------reveal the classification result-----------
    out = circ->PutSharedINGate(node[4], bitlen);
    out = circ->PutOUTGate(out, ALL);
    party->ExecCircuit();
    //output will be the shares of the index of next node
    uint64_t result = out->get_clear_value<uint64_t>();   
// #ifdef DTREE_DEBUG
    cout << "----------reveal---------- \n Classification result in " << (role == SERVER?"server: ":"client: ") << result << endl; 
// #endif
std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) << std::endl;
    party->Reset();

	delete party;
}
