#include "feature_encrypt.h"

extern gmp_randclass gmp_prn;

//key of client
BYTE key4[] = { 0x21, 0xE6, 0xAE, 0x3B,
        0xE7, 0x29, 0x41, 0x0B,
        0xAC, 0x5E, 0xA0, 0x21,
        0x71, 0x46, 0x0D, 0x5A
    };

keyblock lowmc_feature_key = 0x0304;

//real feature although genarated in random...
void ss_real_feature(int num){
    // mpz_class a("123456789");
    // std::cout << a.get_str(2) << std::endl; //base 2 representation
    gmp_prn.seed(time(NULL));
    node_tuple_mz feature(num,1);
    feature.init();
#ifdef DTREE_DEBUG
    printf("************feature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
    for(uint64_t i = 0; i < num; i++){
        prf_aes_128_by_key(i, key4, feature);
    }
#ifdef DTREE_DEBUG
    printf("************encryptedfeature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
}

node_tuple_mz return_feature(uint64_t num, uint64_t featureMax){
    // mpz_class a("123456789");
    // std::cout << a.get_str(2) << std::endl; //base 2 representation
    gmp_prn.seed(time(NULL));
    node_tuple_mz feature(featureMax,1);
    feature.init();
    for(uint64_t i = num; i < featureMax; i++){
        *(feature.plain.data() + i) = 0;
    }
#ifdef DTREE_DEBUG
    printf("************feature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
    for(uint64_t i = 0; i < num; i++){
        prf_aes_128_by_key(i, key4, feature);
    }
#ifdef DTREE_DEBUG
    printf("************encryptedfeature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
    return feature;
}

//this is for test, each evalue of attribute is fixed
node_tuple_mz return_fixed_feature(uint64_t featureDim, uint64_t featureMax){
    // mpz_class a("123456789");
    // std::cout << a.get_str(2) << std::endl; //base 2 representation
    node_tuple_mz feature(featureMax,1);
    for(uint64_t i = 0; i < featureMax; i++){
        if(i < featureDim){
            *(feature.plain.data() + i) = i;
        }else{
            *(feature.plain.data() + i) = 0;
        }
    }
#ifdef DTREE_DEBUG
    printf("************feature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
    for(uint64_t i = 0; i < featureDim; i++){
        prf_aes_128_by_key(i, key4, feature);
    }
#ifdef DTREE_DEBUG
    printf("************encryptedfeature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
    return feature;
}


node_tuple_mz encrypt_fixed_feature(uint64_t featureDim, uint64_t featureMax){
    // mpz_class a("123456789");
    // std::cout << a.get_str(2) << std::endl; //base 2 representation
    node_tuple_mz feature(featureMax,1);
    for(uint64_t i = 0; i < featureMax; i++){
        if(i < featureDim){
            *(feature.plain.data() + i) = i;
        }else{
            *(feature.plain.data() + i) = 0;
        }
    }
#ifdef DTREE_DEBUG
    printf("************feature**********************\n");
    print_ss_tuple_mz(feature);
#endif 

    LowMC lowmc(lowmc_feature_key);

    for(uint64_t i = 0; i < featureDim; i++){
        // std::cout<< i << std::endl;
        block mask = lowmc.encrypt(i); 
        
        mpz_xor_mask(mask, blocksize, *(feature.plain.data() + i));
        // std::cout << "mask " << i << ", " << mask << std::endl;
        // std::cout << "feature " << i << ", " << (*(feature.plain.data() + i)).get_str(2) << std::endl;

       // block mask = lowmc.decrypt(mask); 
        // std::cout << "mask plain " <<  lowmc.decrypt(mask) << std::endl;
    }
    // gmp_printf("After encryption is %Zd\n\n", *(feature.plain.data() + 6));
    

#ifdef DTREE_DEBUG
    printf("************encryptedfeature**********************\n");
    print_ss_tuple_mz(feature);
#endif 
    return feature;
}

//print the ss_tuple_mz
void print_ss_tuple_mz(node_tuple_mz& tuple){
  for (int i = 0, size = tuple.plain.size(); i < size; ++i) {
    std::cout << (*(tuple.plain.data() + i)).get_str(2) << std::endl;
    gmp_printf("plain %d is %Zd\n\n", i, *(tuple.plain.data() + i));
  }
}

void prf_aes_128_by_key(uint64_t num, BYTE key[16], node_tuple_mz & feature){
    BYTE input[16];
    BYTE output[16];
    //int to hex string then to bin
    std::string out;
    std::stringstream ss;
    ss << std::hex << num;
    ss >> out;
    transform(out.begin(), out.end(), out.begin(), ::toupper);
    //std::cout << out << std::endl;
    str2bin(out, input);
    //printstate(input);
    //aes encryption
    p_aes128_encrypt(input, output, key);
    //printstate(output);
    //xor encryption
    aes_xor_class_plain(output, *(feature.plain.data() + num));
}


void prf_aes_128_decrypt_by_key_feature(uint64_t num, mpz_class &result){
    BYTE input[16];
    BYTE output[16];
    //int to hex string then to bin
    std::string out;
    std::stringstream ss;
    ss << std::hex << num;
    ss >> out;
    transform(out.begin(), out.end(), out.begin(), ::toupper);
    str2bin(out, input);
    p_aes128_encrypt(input, output, key4);
    aes_xor_class_plain(output, result);
}