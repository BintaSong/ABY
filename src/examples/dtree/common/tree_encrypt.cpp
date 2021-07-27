#include "tree_encrypt.h"

extern gmp_randclass gmp_prn;

//keys of server
BYTE key1[] = { 0x6E, 0x66, 0xAE, 0x0B,
        0xE7, 0x29, 0x41, 0xEB,
        0xA6, 0x53, 0x10, 0x21,
        0x13, 0x76, 0x08, 0x2E
    };
BYTE key2[] = { 0xda, 0xdf, 0x11, 0xe7, 
        0x4d, 0x01, 0x4a, 0x62, 
        0xd7, 0x3c, 0xca, 0xdd, 
        0x95, 0x91, 0x44, 0x2a
    };
BYTE key3[] = { 0x61, 0xD6, 0xAE, 0x8B,
        0xE7, 0x29, 0x41, 0xEB,
        0xAF, 0x5E, 0x90, 0x21,
        0x73, 0x76, 0x08, 0x2A
    };

keyblock lowmc_tree_key = 0x0304;


void ss_real_tree(DecTree& tree){
    double time_total = 0;
    std::vector<node_tuple_mz> treeV;
    //读出的数据进行赋值
    for(int i = 0;  i < (tree.num_dec_nodes + tree.num_of_leaves); i++){
        node_tuple_mz node(1,5);
        //std::cout << node.plain.size() << std::endl;
        for (int j = 0, size = node.plain.size(); j < size; ++j){
            if(j == 0){
                //std::cout << "test0" << std::endl;
                //std::cout << tree.thres[i].get_ui() << std::endl;
                *(node.plain.data()) = tree.thres[i];
                //*(node.plain.data()) = tree.thres[i].get_ui();
            }else if(j == 1){
                //std::cout << "test1" << std::endl;
                //std::cout << tree.left[i] << std::endl;
                *(node.plain.data() + j) = tree.left[i];
            }else if(j == 2){
                //std::cout << "test2" << std::endl;
                //std::cout << tree.right[i] << std::endl;
                *(node.plain.data() + j) = tree.right[i];
            }else if(j == 3){
                //std::cout << "test3" << std::endl;
                //std::cout << tree.map[i] << std::endl;
                *(node.plain.data() + j) = tree.map[i];
            }else if(j == 4){
                //std::cout << "test4" << std::endl;
                //std::cout << tree.label[i] << std::endl;
                *(node.plain.data() + j) = tree.label[i];
            }
        }
        //std::cout << "*******************************" << std::endl;
        treeV.push_back(node);
    }
    //print_vector_ss_tuple_mz(treeV);

    std::vector<node_tuple_mz> encryptedTreeV;//加密后的密文
    concatenate(treeV, encryptedTreeV);//联接后一个block为128bits,为后面aes加密做准备
    printf("************treeV**********************\n");
    print_vector_ss_tuple_mz(treeV);
    printf("************encryptedTreeV**********************\n");
    print_vector_ss_tuple_mz(encryptedTreeV);
    //aes encryption, different cloumn has different key
    for(uint64_t i = 0; i < tree.num_dec_nodes + tree.num_of_leaves; i++){
        prf_vector_aes_128_by_key(1, i, key1, encryptedTreeV);
        prf_vector_aes_128_by_key(2, i, key2, encryptedTreeV);
        prf_vector_aes_128_by_key(3, i, key3, encryptedTreeV);
    }
    printf("************XORencryptedTreeV**********************\n");
    print_vector_ss_tuple_mz(encryptedTreeV);
}


std::vector<node_tuple_mz> return_tree(DecTree& tree, uint64_t(&array)[5]){
    double time_total = 0;
    std::vector<node_tuple_mz> treeV;
    //初始化root node
    array[0] = mpz2uint64(tree.thres[0]);
    array[1] = mpz2uint64(tree.left[0]);
    array[2] = mpz2uint64(tree.right[0]);
    array[3] = mpz2uint64(tree.map[0]);
    array[4] = mpz2uint64(tree.label[0]);
    //读出的数据进行赋值
    for(int i = 0;  i < (tree.num_dec_nodes + tree.num_of_leaves); i++){
        node_tuple_mz node(1,5);
        *(node.plain.data()) = tree.thres[i];
        *(node.plain.data() + 1) = tree.left[i];
        *(node.plain.data() + 2) = tree.right[i];
        *(node.plain.data() + 3) = tree.map[i];
        *(node.plain.data() + 4) = tree.label[i];
        treeV.push_back(node);
    }
    //print_vector_ss_tuple_mz(treeV);

    std::vector<node_tuple_mz> encryptedTreeV;//加密后的密文
    concatenate(treeV, encryptedTreeV); //联接后一个block为128bits,为后面aes加密做准备 NOTE: DO NOT USE concatenate(treeV, 128, encryptedTreeV) FOR AES VERSION
#ifdef DTREE_DEBUG
    printf("************treeV**********************\n");
    print_vector_ss_tuple_mz(treeV);
    printf("************encryptedTreeV**********************\n");
    print_vector_ss_tuple_mz(encryptedTreeV);
#endif 
    //aes encryption, different cloumn has different key
    for(uint64_t i = 0; i < tree.num_dec_nodes + tree.num_of_leaves; i++){
        prf_vector_aes_128_by_key(1, i, key1, encryptedTreeV);
        prf_vector_aes_128_by_key(2, i, key2, encryptedTreeV);
        prf_vector_aes_128_by_key(3, i, key3, encryptedTreeV);
    }
#ifdef DTREE_DEBUG
    printf("************XORencryptedTreeV**********************\n");
    print_vector_ss_tuple_mz(encryptedTreeV);
#endif 
    return encryptedTreeV;
}

std::vector<node_tuple_mz> encrypt_tree(const DecTree& tree, uint64_t *root_node){
    double time_total = 0;
    std::vector<node_tuple_mz> treeV;
    //初始化root node
    root_node[0] = mpz2uint64(tree.thres[0]);
    root_node[1] = mpz2uint64(tree.left[0]);
    root_node[2] = mpz2uint64(tree.right[0]);
    root_node[3] = mpz2uint64(tree.map[0]);
    root_node[4] = mpz2uint64(tree.label[0]);
    
    //读出的数据进行赋值
    for(int i = 0;  i < (tree.num_dec_nodes + tree.num_of_leaves); i++){
        node_tuple_mz node(1,5);
        *(node.plain.data()) = tree.thres[i];
        *(node.plain.data() + 1) = tree.left[i];
        *(node.plain.data() + 2) = tree.right[i];
        *(node.plain.data() + 3) = tree.map[i];
        *(node.plain.data() + 4) = tree.label[i];
        std::cout << "i: "<< i <<", label: " << tree.label[i] <<std::endl;
        treeV.push_back(node);
    }

    std::vector<node_tuple_mz> encryptedTreeV;//加密后的密文
    concatenate(treeV, blocksize, encryptedTreeV); //联接后一个block为256bits, 最后一个block可能不满

    #ifdef DTREE_DEBUG
        printf("************treeV**********************\n");
        print_vector_ss_tuple_mz(treeV);
        printf("************encryptedTreeV**********************\n");
        print_vector_ss_tuple_mz(encryptedTreeV);
    #endif 

    // encrypt tree by lowmc block cipher
    LowMC lowmc(lowmc_tree_key); 

    uint16_t n_blocks = ceil_divide(sizeof(uint64_t) * 8 * 5, blocksize); 
    for(uint64_t i = 0; i < tree.num_dec_nodes + tree.num_of_leaves; i++) {
        for (uint64_t j = 0; j < n_blocks; j++) {
            std::cout<< i << " -----" << j << std::endl;
            block mask, msg((i<<3)+j); // FIXME: j here is for subindex, j <= 5 for our case, so i << 3 should be sufficient for i||j 
            mask = lowmc.encrypt(msg);
            std::cout << i << " - " << j << " tree mask " <<  mask << std::endl;
            std::cout << i << " - " << j << " tree mask plain " <<  lowmc.decrypt(mask) << std::endl;
            mpz_xor_mask(mask, blocksize, *(encryptedTreeV[i].plain.data()+j));
        }
    }

    #ifdef DTREE_DEBUG
        printf("************XORencryptedTreeV**********************\n");
        print_vector_ss_tuple_mz(encryptedTreeV);
    #endif

    return encryptedTreeV;
}

// void ss_real_tree(DecTree& tree){
//     double time_total = 0;
//     std::vector<ss_tuple_mz> treeV;
//     //读出的数据进行赋值
//     for(int i = 0;  i < (tree.num_dec_nodes + tree.num_of_leaves); i++){
//         ss_tuple_mz node(1,5);
//         //std::cout << node.plain.size() << std::endl;
//         for (int j = 0, size = node.plain.size(); j < size; ++j){
//             if(j == 0){
//                 //std::cout << "test0" << std::endl;
//                 //std::cout << tree.thres[i].get_ui() << std::endl;
//                 *(node.plain.data()) = tree.thres[i];
//                 //*(node.plain.data()) = tree.thres[i].get_ui();
//             }else if(j == 1){
//                 //std::cout << "test1" << std::endl;
//                 //std::cout << tree.left[i] << std::endl;
//                 *(node.plain.data() + j) = tree.left[i];
//             }else if(j == 2){
//                 //std::cout << "test2" << std::endl;
//                 //std::cout << tree.right[i] << std::endl;
//                 *(node.plain.data() + j) = tree.right[i];
//             }else if(j == 3){
//                 //std::cout << "test3" << std::endl;
//                 //std::cout << tree.map[i] << std::endl;
//                 *(node.plain.data() + j) = tree.map[i];
//             }else if(j == 4){
//                 //std::cout << "test4" << std::endl;
//                 //std::cout << tree.label[i] << std::endl;
//                 *(node.plain.data() + j) = tree.label[i];
//             }
//         }
//         //std::cout << "*******************************" << std::endl;
//         treeV.push_back(node);
//     }
//     //print_vector_ss_tuple_mz(treeV);

//     std::vector<ss_tuple_mz> encryptedTreeV;//加密后的密文
//     concatenate(treeV, encryptedTreeV);//联接后一个block为128bits,为后面aes加密做准备
//     printf("************treeV**********************\n");
//     print_vector_ss_tuple_mz(treeV);
//     printf("************encryptedTreeV**********************\n");
//     print_vector_ss_tuple_mz(encryptedTreeV);
//     //aes encryption, different cloumn has different key
//     for(uint64_t i = 0; i < tree.num_dec_nodes + tree.num_of_leaves; i++){
//         prf_vector_aes_128_by_key(1, i, key1, encryptedTreeV);
//         prf_vector_aes_128_by_key(2, i, key2, encryptedTreeV);
//         prf_vector_aes_128_by_key(3, i, key3, encryptedTreeV);
//     }
//     printf("************XORencryptedTreeV**********************\n");
//     print_vector_ss_tuple_mz(encryptedTreeV);
    
//     //dot product by xor
//     mpz_class cfssResult1 = gmp_prn.get_z_bits(CONFIG_C);
//     mpz_class cfssResult2 = gmp_prn.get_z_bits(CONFIG_C);
//     mpz_class cfssResult3 = gmp_prn.get_z_bits(CONFIG_C);
//     //client
//     dotProductXor(0, encryptedTreeV, cfssResult1, cfssResult2, cfssResult3);
//     mpz_class pfssResult1 = gmp_prn.get_z_bits(CONFIG_C);
//     mpz_class pfssResult2 = gmp_prn.get_z_bits(CONFIG_C);
//     mpz_class pfssResult3 = gmp_prn.get_z_bits(CONFIG_C);
//     //provier
//     dotProductXor(1, encryptedTreeV, pfssResult1, pfssResult2, pfssResult3);

//     printf("************result1**********************\n");
//     cout << cfssResult1 << endl;
//     cout << pfssResult1 << endl;
//     //cout << cfssResult1 - pfssResult1 << endl;
//     cout << "ciphertext is " << (pfssResult1 ^ cfssResult1)<< endl;
//     prf_aes_128_decrypt_by_key(1, 2, cfssResult1);
//     cout << cfssResult1 << endl;
//     cout << pfssResult1 << endl;

//     mpz_class cf_de_concate_result0 = gmp_prn.get_z_bits(CONFIG_L);
//     mpz_class cf_de_concate_result1 = gmp_prn.get_z_bits(CONFIG_L);
//     deconcatenate(cfssResult1, cf_de_concate_result0, cf_de_concate_result1);

//     cout << "de_concate_result1 is " << cf_de_concate_result1 << endl;
//     cout << "de_concate_result0 is " << cf_de_concate_result0 << endl;

//     mpz_class pf_de_concate_result0 = gmp_prn.get_z_bits(CONFIG_L);
//     mpz_class pf_de_concate_result1 = gmp_prn.get_z_bits(CONFIG_L);
//     deconcatenate(pfssResult1, pf_de_concate_result0, pf_de_concate_result1);

    
//     cout << "de_concate_result1 is " << pf_de_concate_result1 << endl;
//     cout << "de_concate_result0 is " << pf_de_concate_result0 << endl;


//     cout << "plaintext is " << (pfssResult1 ^ cfssResult1) << endl;
//     // printf("************result2**********************\n");
//     // cout << cfssResult2 << endl;
//     // cout << pfssResult2 << endl;
//     // printf("************result3**********************\n");
//     // cout << cfssResult3 << endl;
//     // cout << pfssResult3 << endl;

//     //TODO secure computation of PRF, secure comparison, secure multiplexer  
// }


//print the vector ss_tuple_mz
void print_vector_ss_tuple_mz(std::vector<node_tuple_mz>& tuple){
    for (std::vector<node_tuple_mz>::iterator it = tuple.begin();
         it < tuple.end(); it++) {
      mpz_class *dataplain = it->plain.data();
      for (int i = 0, size = it->plain.size(); i < size; ++i){
          std::cout << (*(dataplain + i)).get_str(2) << std::endl;
          gmp_printf("plain%d is %Zd\n", i, *(dataplain + i));
      }
      printf("\n");
    }
}

//前四个采取顺次级联。对第五个，为了保持数据的易读性，对低位（64-127位bit）补零。
void concatenate(std::vector<node_tuple_mz>& treeV, std::vector<node_tuple_mz>& encryptedTreeV){
    mpz_class data[3];
    mpz_class div = pow(2, 64);
    matrix_z dataV(1,3);//matrix needs parameters if we want to use it in the following
    for(std::vector<node_tuple_mz>::iterator it = treeV.begin(); it < treeV.end(); it++){
        mpz_class *dataplain = it->plain.data();
        //concatenate, 5 to 3
        int size = it->plain.size();
        for(int i = 0; i < size; i = i+2){
            
            if((i+1) == size){
                data[i/2] = div * (*(dataplain + i));
            }else{
                data[i/2] = div * (*(dataplain + i)) + (*(dataplain + (i+1)));
            }
        }
        //print data after concatenation
        // for (int i = 0; i < size/2 + 1; i++){
        //     gmp_printf("data[%d] is %Zd\n", i, data[i]);
        // }
        //assin data array to a new vector
        for (int i = 0; i < size/2 + 1; ++i) {
            //printf("test\n");
            *(dataV.data() + i) = data[i];
        }
        //print data after creating a tuple
        node_tuple_mz dataNode(dataV, 1, size/2 + 1);
        // printf("data node size is %ld\n", dataNode.plain.size());
        // for(int i = 0; i < dataNode.plain.size(); i++){
        //     gmp_printf("data is %Zd\n", *(dataNode.plain.data()+i));
        // }
        encryptedTreeV.push_back(dataNode);
    }
}

void concatenate(std::vector<node_tuple_mz>& treeV, const uint16_t block_bitsize, std::vector<node_tuple_mz>& encryptedTreeV){
    // FIXME: so far block_size needs to be multiple of 64 bits

    uint16_t node_elements_num = treeV.begin()->plain.size(); // the number of elements in a tree node
    uint16_t block_elements_num = block_bitsize / 64; // the number of elements in a block
    //uint16_t node_blocks_num = (uint16_t) ((node_elements_num * 64 + block_size - 1) / block_size); // number of blocks for a tree node 
    uint16_t node_blocks_num = ceil( ((double) node_elements_num * 64 / block_bitsize) );
    matrix_z blocks(1, node_blocks_num); 

    for(std::vector<node_tuple_mz>::iterator it = treeV.begin(); it < treeV.end(); it++){
        
        mpz_class *node_ptr = it->plain.data();
        
        for (uint16_t i = 0; i < node_blocks_num; i++) {
            
            mpz_class block = 0;
            
            for (uint16_t j = 0; j < block_elements_num && i*block_elements_num+j < node_elements_num; j++) {
                
                block = (block << 64) + *(node_ptr + i*block_elements_num+j);
                
            }
            *(blocks.data() + i) = block; 
        }

        node_tuple_mz block_tuple(blocks, 1, node_blocks_num);
        encryptedTreeV.push_back(block_tuple);    
    }
}

void deconcatenate(mpz_class blocks[], uint16_t n_blocks, uint64_t nodes[]){
    // this is a method for parsing lowmc blocks ot nodes 
    /*
        FIXME: for blocksize = 256, blocks are pakced as:

        |----------------block 0---------------|--block 1--|
        |  node[0], node[1], node[2], node[3]  |  node[4]  |
    
    */
    uint16_t n_elements = ceil_divide(blocksize, 64);

    uint16_t index, r_position;
    mpz_class block, element; 

    for (uint16_t i = 0; i < n_blocks; i++) {
        block = blocks[i];
        for (uint16_t j = 0; j < n_elements; j++) {
            
            if (i * n_elements + j >= 5) return ;

            element = block % pow(2, 64);
            block >>= 64;

            r_position = (5 - n_elements * i) > n_elements ? n_elements : 5 - n_elements * i;

            index = n_elements * i + r_position - 1 - j;
            nodes[index] = mpz2uint64(element);

            std::cout << "n_blocks " << n_blocks  << ", block " << i << ", elments " << j << ", index " << index << ": " << element.get_str(2) << std::endl; 
        }
    }
}

// void deconcatenate(mpz_class concate_result, mpz_class& de_concate_result0, mpz_class& de_concate_result1){
//     mpz_class div = pow(2, 64);
//     de_concate_result0 = concate_result%div;//余数为低位
//     de_concate_result1 = concate_result/div;//商为高位
// }

//将128bit数分解为两个64位数。de_concate_result0为低64位，de_concate_result1为高64位
void deconcatenate(mpz_class concate_result, mpz_class& de_concate_result0, mpz_class& de_concate_result1){
    mpz_class div = pow(2, 64);
    de_concate_result0 = concate_result%div;//余数为低位
    de_concate_result1 = concate_result/div;//商为高位
}

void prf_vector_aes_128_by_key(int tag, uint64_t num, BYTE key[16], 
std::vector<node_tuple_mz>& encryptedTreeV){
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

    aes_xor_class_plain(output, *(encryptedTreeV[num].plain.data() + tag - 1));
}

void prf_vector_lowmc_by_key(int tag, uint64_t num, BYTE* key, size_t key_length, std::vector<node_tuple_mz>& encryptedTreeV) {
    
}

void prf_aes_128_decrypt_by_key(int tag, uint64_t num, mpz_class &result){
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
    if(tag == 1){
        p_aes128_encrypt(input, output, key1);
    }else if(tag == 2){
        p_aes128_encrypt(input, output, key2);
    }else if(tag == 3){
        p_aes128_encrypt(input, output, key3);
    }else{
        cout << "wrong tag in prf_aes_128_by_key!" << endl;
    }
    aes_xor_class_plain(output, result);
}




void prf_lowmc_decrypt_by_key(int tag, uint64_t num, mpz_class &result) {

}
