#include "fss_or_ot.h"
string testfssResultFile1 = "../../src/examples/dtree/fss/ZeroOrOne0.txt";
string testfssResultFile2 = "../../src/examples/dtree/fss/ZeroOrOne1.txt";
string testOTKFile = "../../src/examples/dtree/K.txt";

//定义一些时间参数
auto start = std::chrono::steady_clock::now(), stop = std::chrono::steady_clock::now();
#define CLOCK_START {start = std::chrono::steady_clock::now();}
#define CLOCK_STOP {stop = std::chrono::steady_clock::now();}
#define ELAPSED std::chrono::duration<double, std::nano>(stop - start).count()//一段时间

//key of client
BYTE testkeyc4[] = { 0x21, 0xE6, 0xAE, 0x3B,
        0xE7, 0x29, 0x41, 0x0B,
        0xAC, 0x5E, 0xA0, 0x21,
        0x71, 0x46, 0x0D, 0x5A
    };

BYTE testlowmc_server_key[] = {0x04, 0x03, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0
    };

BYTE testlowmc_client_key[] = {0x04, 0x03, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0, 
        0x0, 0x0, 0x0, 0x0
    };


void fssorot_feature(e_role role, char* address, uint16_t port, seclvl seclvl, 
                        uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, 
                        e_sharing sharing, string filename, uint64_t featureDim, 
                        uint64_t r, uint32_t depth, uint32_t nvals, 
                        [[maybe_unused]] bool verbose, bool use_vec_ands, 
                        bool expand_in_sfe, bool client_only){
    uint64_t featureMax = pow(2, ceil(log(featureDim)/log(2)));
    uint64_t attri;
    double time_total = 0;

    /*
    //generating random attribute values of feature vector
    node_tuple_mz encryptedFeature = return_feature(featureDim, featureMax);
    */

    //for test....generating fixed attribute values of feature vector

#if DTREE_FEAREAD_BY_OT

    uint64_t *initAttr, *sentAttri, *rcvAttri;
    initAttr = (uint64_t*) malloc(featureDim * sizeof(uint64_t));
	sentAttri = (uint64_t*) malloc(featureDim * sizeof(uint64_t));
    rcvAttri = (uint64_t*) malloc(featureDim * sizeof(uint64_t));

    vector<uint64_t> OTK;
    if(role == CLIENT){
        attri = 666864304155736222;
        for(int i = 0; i < featureDim; i++){
            initAttr[i] = i;
        }
        OTKRead(testOTKFile, OTK, featureDim);
    }

#else

#if DTREE_ENCRYPTED_BY_LOWMC 
    node_tuple_mz encryptedFeature = encrypt_fixed_feature(featureDim, featureMax);
#else
    node_tuple_mz encryptedFeature = return_fixed_feature(featureDim, featureMax);
#endif 
    //-----------Read Evaluation Result of FSS for feature----------------
    vector<int> zeroOrOneFt;
    FSSFeatureRead(role, testfssResultFile1, testfssResultFile2, zeroOrOneFt, featureMax, featureDim);

#endif

    uint64_t node;
    

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
    uint64_t out_delta;
    
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
            raw_server_key.SetBytes(testlowmc_server_key, 0, keysize/8);
            keyschedule(raw_server_key, extend_server_key, &param);
	    }
        else if(role == CLIENT) {
            raw_client_key.SetBytes(testlowmc_client_key, 0, keysize/8);
            keyschedule(raw_client_key, extend_client_key, &param);
        }
    #endif
    uint32_t r_server = 2;
    uint32_t r_client = 0;
    for(int i = 0; i < depth; i++){
    #ifdef DTREE_DEBUG
        std::cout << "\n*****************this is in depth " << i << "******************" << endl; 
    #endif
    if(role == SERVER){
      node = 5;
    }else if(role == CLIENT){
      node = 6;
    }
    #if DTREE_FEAREAD_BY_OT
        // reveal difference for OT, r is known to server, we suppose here it is 2.
        if(role == SERVER){
            s_a = circ->PutINGate(r_server, bitlen, SERVER);//2
        }else if(role == CLIENT){
            s_a = circ->PutINGate(r_client, bitlen, CLIENT);//0
        }
        // s_a = circ->PutSharedINGate(r, bitlen);//2
        s_b = circ->PutSharedINGate(node, bitlen);//6
        //s_a = ac->PutB2AGate(s_a);
        s_b = ac->PutB2AGate(s_b);
        s_c = ac->PutSUBGate(s_b, s_a);//b-a
        out = ac->PutOUTGate(s_c, ALL);
        // Execute again and get the reconstructed result
        party->ExecCircuit();
        //avoid negtive number by adding featureDim, because the offset should be positive
        if(out->get_clear_value<int64_t>() < 0){
            out_delta = out->get_clear_value<int64_t>() + featureDim;
        }else{
            out_delta = out->get_clear_value<uint64_t>();
        }
    #ifdef DTREE_DEBUG
        cout << "out_delta of tree" << (role == SERVER?"server: ":"client: ") << out_delta << std::endl; // here output the shared value.
    #endif
        party->Reset();

        //client sends encrypted feature to the server
        if(role == CLIENT){
            for(int i = 0; i < featureDim; i++){
                sentAttri[i] = OTK[i] ^ initAttr[(i+out_delta)%featureDim] ^ attri;
            }
            s_a = circ->PutSharedSIMDINGate(featureDim, sentAttri, bitlen);
        }else{
            for(int i = 0; i < featureDim; i++){
                sentAttri[i] = 0;
            }
            s_a = circ->PutSharedSIMDINGate(featureDim, sentAttri, bitlen);
        }
        out = circ->PutOUTGate(s_a, ALL);
        party->ExecCircuit();
        uint32_t tmpbitlen, tmpnvals;
        out->get_clear_value_vec(&rcvAttri, &tmpbitlen, &tmpnvals);
        party->Reset();

        if(role == SERVER){
            uint64_t OTK2 = 1753871613581113959;//read from the file
            attri = rcvAttri[2] ^ OTK2;
        }
    #else 

    #if DELTA_XOR
        //-----------Compute out_delta = r ^ node by Mpc----------------
        s_a = circ->PutSharedINGate(r, bitlen);
        s_b = circ->PutSharedINGate(node, bitlen);

        out = circ->PutXORGate(s_a, s_b);
        out = circ->PutOUTGate(out, ALL);//public out_delta

        party->ExecCircuit();

        out_delta = out->get_clear_value<uint64_t>();
    #ifdef DTREE_DEBUG
        cout << (role == SERVER?"server feature out_delta: ":"client feature out_delta: ") << (int) out_delta << endl; // here output the shared value.
    #endif
        party->Reset();
    #else  

    // compute out_delta = b-a
        // r is known to server, we suppose here it is 2.
        if(role == SERVER){
            s_a = circ->PutINGate(r_server, bitlen, SERVER);//2
        }else if(role == CLIENT){
            s_a = circ->PutINGate(r_client, bitlen, CLIENT);//0
        }
        // s_a = circ->PutSharedINGate(r, bitlen);//2
        s_b = circ->PutSharedINGate(node, bitlen);//6
        //s_a = ac->PutB2AGate(s_a);
        s_b = ac->PutB2AGate(s_b);
        s_c = ac->PutSUBGate(s_b, s_a);//b-a
        out = ac->PutOUTGate(s_c, ALL);
        // Execute again and get the reconstructed result
        party->ExecCircuit();
        //avoid negtive number by adding featureDim, because the offset should be positive
        if(out->get_clear_value<int64_t>() < 0){
            out_delta = out->get_clear_value<int64_t>() + featureDim;
        }else{
            out_delta = out->get_clear_value<uint64_t>();
        }
        party->Reset();
    #endif

    #if DELTA_XOR
        //-----------Compute shared attribute value----------------
        mpz_class sharedAttri = 0;
        CLOCK_START
        for (int i = 0; i < featureMax; i++) {
            sharedAttri = (*(encryptedFeature.plain.data() +(i^out_delta)) * zeroOrOneFt[i]) ^ sharedAttri;
        }
        CLOCK_STOP
        time_total += ELAPSED;
    #else
       //-----------Compute shared attribute value----------------
        mpz_class sharedAttri = 0;
        CLOCK_START
        for (int i = 0; i < featureMax; i++) {
            sharedAttri = (*(encryptedFeature.plain.data()+ (i+out_delta)%featureDim) * zeroOrOneFt[i]) ^ sharedAttri;
        }
        CLOCK_STOP
        time_total += ELAPSED;
    #endif

    #if DTREE_ENCRYPTED_BY_LOWMC
        // do two-party lowmc evaluation
        BYTE index_share[blocksize/8], lowmc_share[blocksize/8];
        memset(index_share, 0, blocksize/8);
        memcpy(index_share, &node, sizeof(uint64_t)); // indeed, node[3]'s length is 8 bytes 
        

        lowmc_circuit_shared_input(role, 1, crypt, sharing, party, sharings, circ, &param, extend_client_key, index_share, lowmc_share, CLIENT);

        mpz_xor_mask(lowmc_share, blocksize, sharedAttri); // now sharedAttri is decrypted and shared between parties
        party->Reset();
    #else
        BYTE indShared[16];
        aes_circuit_feature(role, nvals, sharing,  party, crypt, sharings, circ, node, indShared, testkeyc4, verbose, use_vec_ands, expand_in_sfe, client_only);
        party->Reset();
        aes_xor_class_plain(indShared, sharedAttri);// server and client do xor locally
    #endif

    #if DTREE_ENCRYPTED_BY_LOWMC 
    // std::cout << "lowmc1" << std::endl;    
    sharedAttri = sharedAttri % pow(2, 64); 
    // std::cout << " Decrypted attribute mod 2^64 share is: " << sharedAttri.get_str(2) << std::endl; 
        attri = mpz2uint64(sharedAttri);   

    #else
        //we deconcatenate 128bits to 64bits
        deconcatenate(sharedAttri, attri);
    #endif

    #endif

    } //end for

	delete party;
    cout << "Local run time is " << time_total/1000000 << endl;
}
