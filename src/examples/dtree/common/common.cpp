#include "common.h"

// 低位补零
void str2bin(const std::string& in, unsigned char out[]){
    const char* data = in.data();
    const std::string::size_type size = in.size();
    // cout << "size is " << size << endl;
    if(size%2 == 0){//偶数位
        for(std::string::size_type i = 0; i < size; i+= 2){
            unsigned int tmp;
            std::sscanf(data + i, "%02X", &tmp);
            out[15-(size/2)+(i / 2)+1] = tmp;
        }
        for (std::string::size_type i = 0; i < (15 -(size/2)); i++) {
            out[i] = 0x00;
        }
    }else{//奇数位
        std::string s;
        s = in.substr(0, 1);
        // cout << "s is " << s << endl; 
        const char* subdata = s.data();
        unsigned int tmp;
        std::sscanf(subdata+0, "%02X", &tmp);
        out[15 - (size / 2)] = tmp;
        for (std::string::size_type i = 1; i < size; i += 2) {
            unsigned int tmp;
            std::sscanf(data + i, "%02X", &tmp);
            out[15 - (size / 2) + (i / 2) + 1] = tmp;
        }
        for(std::string::size_type i = 0; i < (15 -(size/2)-1); i++){
            out[i] = 0x00;
        }
    }
    
}
// // 高位补零
// void str2bin(const std::string& in, unsigned char out[]){
//     const char* data = in.data();
//     const std::string::size_type size = in.size();
//     for(std::string::size_type i = size - 1; i <= 0; i-= 2) {
//         unsigned int tmp;
//         for(int j = 0; j < size; j+=2){
//             std::sscanf(data+j, "%02X", &tmp);
//         }        
//         out[i/2] = tmp;
//     }
//     for(std::string::size_type i = 0; i < (size+1)/2; i--){
//         out[i] = 0x00;
//     }
// }

void aes_xor_class_plain(BYTE in[16], mpz_class& plain){
    //gmp_printf("plain before xor is %Zd\n", plain.get_mpz_t());
    mpz_class tmp;
    //高位在in[0], 低位在in[16]
    for(int i = 0; i < 16; i++){
        for(int j = 0; j < 8; j++){
            if(in[i] & ((uint8_t)1 << j))
                mpz_setbit(tmp.get_mpz_t(), 8*i+j);
        }
    }
    plain = plain ^ tmp;
#ifdef DTREE_DEBUG
    gmp_printf("plain is %Zd\n", plain.get_mpz_t());
#endif
}

// block to_little_end(block msg) {
//     uint16_t msg_len = msg.size();
    
//     assert ( msg_len % 8 == 0);
    
//     for (uint)

// }

void mpz_xor_mask(block mask, uint16_t mask_bitlen, mpz_class& plain){
    /*
        `mask`: the mask to be xored with `plain` 
        `plain`: the mpz_class value needs to be xored, for this function |`plain`| == |mask|

        NOTE: we need to use mask in little-end !!
    */

    assert(mask.size() == mask_bitlen); 

    mpz_class tmp;
    for (uint16_t i = 0; i < mask_bitlen; i++) {
        
        //uint16_t m = i / 8, n = i % 8;

        if (mask[i]) {
            mpz_setbit(tmp.get_mpz_t(), i);
        }
    }
    plain = plain ^ tmp;

    #ifdef DTREE_DEBUG
        gmp_printf("plain is %Zd\n", plain.get_mpz_t());
    #endif
}

void mpz_xor_mask(BYTE *mask, uint16_t mask_len, mpz_class& plain) {
    /*
        `mask`: the mask to be xored with `plain` 
        `plain`: the mpz_class value needs to be xored, for this function |`plain`| == |mask|
        
        NOTE: mask is encoded as little-end 
    */
    mpz_class tmp;
    for (uint16_t i = 0; i < mask_len; i++) {
        uint16_t m = i / 8, n = i % 8;

        if ( mask[m] & ((uint16_t)1 << n) ) {
            mpz_setbit(tmp.get_mpz_t(), i);
        }
    }
    plain = plain ^ tmp;

    #ifdef DTREE_DEBUG
        gmp_printf("plain is %Zd\n", plain.get_mpz_t());
    #endif
}

//将128bit数分解为两个64位数。de_concate_result0为低64位，de_concate_result1为高64位,因为低位为64个零，这里只取高位
void deconcatenate(mpz_class concate_result, mpz_class& de_concate_result1){
    mpz_class div = pow(2, 64);
    de_concate_result1 = concate_result/div;//商为高位
}

//将128bit数分解为两个64位数。de_concate_result0为低64位，de_concate_result1为高64位,因为低位为64个零，这里只取高位
void deconcatenate(mpz_class concate_result, uint64_t& de_concate_result1){
    mpz_class div64 = pow(2, 64);

    mpz_class tmp64 = concate_result / div64; //商为高位
    de_concate_result1 = mpz2uint64(tmp64);
}


//将128bit数分解为两个64位数。de_concate_result0为低64位，de_concate_result1为高64位
void deconcatenate(mpz_class concate_result, uint64_t& de_concate_result1, uint64_t& de_concate_result0){
    mpz_class div64 = pow(2, 64);

    mpz_class h_tmp64 = concate_result / div64; //商为高位
    de_concate_result1 = mpz2uint64(h_tmp64);

    mpz_class l_tmp64 = concate_result % div64; //余数为低位
    de_concate_result0 = mpz2uint64(l_tmp64);
      
}

uint64_t mpz2uint64(mpz_class z)
{
    uint64_t result = 0;
    mpz_export(&result, 0, -1, sizeof(result), 0, 0, z.get_mpz_t());
    return result;
}

void FSSFeatureRead(e_role role, string file1, string file2, vector<int>& zeroOrOne, int num, int dim){
    //-----------Read Evaluation Result of FSS----------------
    for(uint64_t i = 0; i < num; i++){
		zeroOrOne.push_back(0);
	}
    string line;
    int i = 0;
    if(role == SERVER){//suppose we have enough results
        ifstream file;
        file.open(file1);
        if (!file)  //条件成立，则说明文件打开出错
        cout << "open " << file1 << " errors" << endl;
#ifdef DTREE_DEBUG
        std::cout << "Reading from " << file1 << std::endl;
#endif 
        while (getline(file, line) && i < dim){
            zeroOrOne[i] = atoi(line.c_str());
            i++;
        }
        file.close();
    }else if(role == CLIENT){//suppose we have enough results
        ifstream file;
        file.open(file2);
        if (!file)  //条件成立，则说明文件打开出错
        cout << "open " << file2 << " errors" << endl;
#ifdef DTREE_DEBUG
        cout << "Reading from " << file2 << endl;
#endif 
        while (getline(file, line) && i < dim){
            zeroOrOne[i] = atoi(line.c_str());
            i++;
        }
        file.close();
    }
}

void FSSTreeRead(e_role role, string file1, string file2, vector<int>& zeroOrOne, int num){
    //-----------Read Evaluation Result of FSS----------------
    string line;
    int i = 0;
    if(role == SERVER){//suppose we have enough results
        ifstream file;
        file.open(file1);
#ifdef DTREE_DEBUG
        std::cout << "Reading from " << file1 << std::endl;
#endif 
        while (getline(file, line) && i < num){
            zeroOrOne.push_back(atoi(line.c_str()));
            i++;
        }
        file.close();
    }else if(role == CLIENT){//suppose we have enough results
        ifstream file;
        file.open(file2);
#ifdef DTREE_DEBUG
        cout << "Reading from " << file2 << endl;
#endif         
        while (getline(file, line) && i < num){
            zeroOrOne.push_back(atoi(line.c_str()));
            i++;
        }
        file.close();
    }
}

