#include <chrono>//时间头文件
#include <fstream>//写文件
#include "fss-common.h"
#include "fss-server.h"
#include "fss-client.h"
#include <iostream>
#include <vector>

using namespace std;

// void fssEvaluation(){
//     uint64_t a = 3;//64 bits unsigned long
//     uint64_t b = 1;
//     Fss fClient, fServer;
//     ServerKeyEq k0;
//     ServerKeyEq k1;
//     // Initialize client, use 10 bits in domain as example
//     initializeClient(&fClient, 10, 2); 
    
//     // Equality FSS test
//     //cout << "****Equality FSS test****" << endl;

//     generateTreeEq(&fClient, &k0, &k1, a, b);

//     initializeServer(&fServer, &fClient);
//     mpz_class ans0, ans1, fin;
//     bool tr;
//     //terminal test
//     ans0 = evaluateEq(&fServer, &k0, 719, tr);
//     ans1 = evaluateEq(&fServer, &k1, 719, tr);
//     cout << ans0 << "\t" << tr << endl;
//     cout << ans1 << "\t" << tr << endl;
//     //write to files
//     ofstream OutFile1("EvaluationResult1.txt"); //利用构造函数创建txt文本，并且打开该文本
//     ofstream OutFile2("EvaluationResult2.txt"); 
//     //bool tr;
//     for(int i = 1; i < 100; i++){
//       ans0 = evaluateEq(&fServer, &k0, i, tr);
//       OutFile1 << tr << endl;
//       ans1 = evaluateEq(&fServer, &k1, i, tr);
//       OutFile2 << tr << endl;
//     }
//     OutFile1.close(); //关闭FSSEvaluationTime.txt文件
//     OutFile2.close(); //关闭FSSEvaluationTime.txt文件
// }

void fssEvaluation(){
    uint64_t a = 3;//64 bits unsigned long
    uint64_t b = 1;
    Fss fClient, fServer;
    ServerKeyEq k0;
    ServerKeyEq k1;
    
    // Equality FSS test
    //cout << "****Equality FSS test****" << endl;
    //write keys to files

    //save fss-keys, params
    ofstream OutKey0("Key0.csv"); //利用构造函数创建txt文本，并且打开该文本
    ofstream OutKey1("Key1.csv");
    ofstream ClientParam("ClientParam.csv");
    for(a = 0; a < 1; a++){
        // Initialize client, use 10 bits in domain as example
        initializeClient(&fClient, 10, 2); 
        generateTreeEq(&fClient, &k0, &k1, a, b);
        OutKey0 << k0.s[0] << "\t" <<  k0.s[1] << "\t" 
                << k0.t[0] << "\t" << k0.t[1] << "\t" 
                << *(k0.cw[0])->cs[0] << "\t" << *(k0.cw[0])->cs[1] << "\t" 
                << *(k0.cw[1])->cs[0] << "\t" << *(k0.cw[1])->cs[1] << "\t" 
                << *(k0.cw[0])->ct
                << *(k0.cw[1])->ct
                << k0.w << endl;
        OutKey1 << k1.s[0] << "\t" <<  k1.s[1] << "\t" 
                << k1.t[0] << "\t" << k1.t[1] << "\t" 
                << *(k1.cw[0])->cs[0] << "\t" << *(k1.cw[0])->cs[1] << "\t" 
                << *(k1.cw[1])->cs[0] << "\t" << *(k1.cw[1])->cs[1] << "\t" 
                << *(k1.cw[0])->ct
                << *(k1.cw[1])->ct
                << k1.w << endl;
        ClientParam << fClient.numKeys << "\t"
                    << fClient.aes_keys << "\t" << fClient.numBits << "\t"
                    << "\t" << fClient.numParties << "\t"
                    << fClient.prime << endl;
    }

    //----------initializeServer-----------------
    ifstream file;
    file.open("ClientParam.csv");
    if (!file)  //条件成立，则说明文件打开出错
        cout << "open errors" << endl;
    string line;
    std::vector<string> tokens;
    while (getline(file, line)){
      tokens.clear();
      std::size_t prev = 0, pos;
      while ((pos = line.find_first_of("\t", prev)) != std::string::npos) {
        if (pos > prev)
          tokens.push_back(line.substr(prev, pos - prev));
        prev = pos + 1;
      }
      fServer.numKeys = atoi(tokens[0].c_str());
      fServer.aes_keys = (AES_KEY *)malloc(sizeof(AES_KEY) * fServer.numKeys);
      //This part should be wrong
      for (int i = 0; i < fServer.numKeys; i++) {
        unsigned char rand_bytes[16];
        for (int j = 0; j < 16; j++) {
            rand_bytes[j] = tokens[1][j+2];
        }
      aesni_set_encrypt_key(rand_bytes, 128, &(fServer.aes_keys[i]));
      }//

      memcpy(fServer.aes_keys, fClient.aes_keys, sizeof(AES_KEY) * fServer.numKeys);
      fServer.numBits = atoi(tokens[2].c_str());
      fServer.numParties = atoi(tokens[3].c_str());
      fServer.prime = atol(tokens[4].c_str());
    }
    fServer.numKeys = fClient.numKeys;
    fServer.aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*fClient.numKeys);
    memcpy(fServer.aes_keys, fClient.aes_keys, sizeof(AES_KEY)*fClient.numKeys);
    fServer.numBits = fClient.numBits;
    fServer.numParties = fClient.numParties;
    fServer.prime = fClient.prime;


    mpz_class ans0, ans1;
    bool tr;
    // //terminal test
    // ans0 = evaluateEq(&fServer, &k0, 719, tr);
    // ans1 = evaluateEq(&fServer, &k1, 719, tr);
    // cout << ans0 << "\t" << tr << endl;
    // cout << ans1 << "\t" << tr << endl;

    
    //---------------generating fss evaluations in advance
    ofstream OutFile1("ZeroOrOne1.txt"); //利用构造函数创建txt文本，并且打开该文本
    ofstream OutFile2("ZeroOrOne2.txt"); 
    //bool tr;
    for(int i = 1; i < 100; i++){
      ans0 = evaluateEq(&fServer, &k0, i, tr);
      OutFile1 << tr << endl;
      ans1 = evaluateEq(&fServer, &k1, i, tr);
      OutFile2 << tr << endl;
    }

    // OutKey1.close();
    // OutKey2.close();
    ClientParam.close();
    OutFile1.close(); //关闭FSSEvaluationTime.txt文件
    OutFile2.close(); //关闭FSSEvaluationTime.txt文件
}


int main()
{
    // // Set up variable. Q: why set a as 3, b as 2? A: this is defined as the point function
    // //f_a,_b(x,y):y = b if x = a, y = 0 if x != a
    // uint64_t a = 3;//64 bits unsigned long
    // uint64_t b = 1;
    // Fss fClient, fServer;
    // ServerKeyEq k0;
    // ServerKeyEq k1;

    // // Initialize client, use 10 bits in domain as example
    // initializeClient(&fClient, 10, 2); 
    
    // // Equality FSS test
    // cout << "****Equality FSS test****" << endl;
    // generateTreeEq(&fClient, &k0, &k1, a, b);
    
    // // Initialize server
    // initializeServer(&fServer, &fClient);
    // mpz_class ans0, ans1, fin;
    
    // ans0 = evaluateEq(&fServer, &k0, a);//x = a
    // ans1 = evaluateEq(&fServer, &k1, a);//x = a
    // cout << "ans0 is " << ans0 << endl;
    // cout << "ans1 is " << ans1 << endl;
    // fin = ans0 - ans1;
    // cout << "FSS Eq Match (should be non-zero): " << fin << endl;//since x = a
    
    // ans0 = evaluateEq(&fServer, &k0, (a-1));//x != a
    // ans1 = evaluateEq(&fServer, &k1, (a-1));//x != a
    // cout << "ans0 is " << ans0 << endl;
    // cout << "ans1 is " << ans1 << endl;
    // fin = ans0 - ans1;
    // cout << "FSS Eq No Match (should be 0): " << fin << endl;//since x != a

    // // Less than FSS test
    // cout << "****Less than FSS test****" << endl;
    // ServerKeyLt lt_k0;
    // ServerKeyLt lt_k1;
    
    // initializeClient(&fClient, 10, 2);
    // generateTreeLt(&fClient, &lt_k0, &lt_k1, a, b);

    // initializeServer(&fServer, &fClient);
    // uint64_t lt_ans0, lt_ans1, lt_fin;

    // lt_ans0 = evaluateLt(&fServer, &lt_k0, (a-1));
    // lt_ans1 = evaluateLt(&fServer, &lt_k1, (a-1));
    // cout << "ans0 is " << ans0 << endl;
    // cout << "ans1 is " << ans1 << endl;
    // lt_fin = lt_ans0 - lt_ans1;
    // cout << "FSS Lt Match (should be non-zero): " << lt_fin << endl;

    // lt_ans0 = evaluateLt(&fServer, &lt_k0, a);
    // lt_ans1 = evaluateLt(&fServer, &lt_k1, a);
    // cout << "ans0 is " << ans0 << endl;
    // cout << "ans1 is " << ans1 << endl;
    // lt_fin = lt_ans0 - lt_ans1;
    // cout << "FSS Lt No Match (should be 0): " << lt_fin << endl;

    // // // Equality FSS test for multi-parties

    // // MPKey mp_keys[3];
    // // initializeClient(&fClient, 10, 3);
    // // generateTreeEqMParty(&fClient, a, b, mp_keys);

    // // initializeServer(&fServer, &fClient);
    // // uint32_t mp_ans0 = evaluateEqMParty(&fServer, &mp_keys[0], a);
    // // uint32_t mp_ans1 = evaluateEqMParty(&fServer, &mp_keys[1], a);
    // // uint32_t mp_ans2 = evaluateEqMParty(&fServer, &mp_keys[2], a);
    // // uint32_t xor_mp = mp_ans0 ^ mp_ans1 ^ mp_ans2;
    // // cout << "FSS Eq Multi-Party Match (should be non-zero): " << xor_mp << endl;

    // // mp_ans0 = evaluateEqMParty(&fServer, &mp_keys[0], (a+1));
    // // mp_ans1 = evaluateEqMParty(&fServer, &mp_keys[1], (a+1));
    // // mp_ans2 = evaluateEqMParty(&fServer, &mp_keys[2], (a+1));
    // // xor_mp = mp_ans0 ^ mp_ans1 ^ mp_ans2;
    // // cout << "FSS Eq Multi-Party No Match (should be 0): " << xor_mp << endl;

    // //Total time test of evaluation
    // // size_t rounds = 100000;
    // // auto t_begin = std::chrono::high_resolution_clock::now();
    // // for(size_t i=0; i<rounds; i++) {
    // //     volatile auto x = evaluateEq(&fServer, &k0, i);
    // // }
    // // for(size_t i=0; i<rounds; i++) {
    // //     volatile auto x = evaluateLt(&fServer, &lt_k0, i);
    // // }
    // // for(size_t i=0; i<rounds; i++) {
    // //     volatile auto x = evaluateEqMParty(&fServer, &mp_keys[1], a);
    // // }
    // // auto t_end = std::chrono::high_resolution_clock::now();
    // // std::cout << "Benchmark result: " <<
    // //  std::chrono::duration<double, std::milli>(t_end - t_begin).count()
    // //  << " ms" << endl;

    // //FSSEvaluation Time Equality

    // ofstream OutFile("FSSEvaluationTime.txt"); //利用构造函数创建txt文本，并且打开该文本
    // size_t rounds = 50;
    // for (size_t j = 1; j < rounds; j = j + 5) {
    //   auto t_begin = std::chrono::high_resolution_clock::now();
    //   for (size_t i = 0; i < j; i++) {
    //     volatile auto x = evaluateEq(&fServer, &k0, i);
    //   }
    //   auto t_end = std::chrono::high_resolution_clock::now();

    //   OutFile << std::chrono::duration<double, std::milli>(t_end - t_begin).count()
    //       << endl;
    // }
    // OutFile.close(); //关闭FSSEvaluationTime.txt文件


    // //FSSKeyGen Time Equality
    // uint64_t ag;//64 bits unsigned long
    // uint64_t bg = 1;
    // uint64_t roundsg = 50;

    // // Initialize client, use 10 bits in domain as example
    // initializeClient(&fClient, 10, 2); 
    // ofstream OutFileG("FSSKeyGenTime.txt"); //利用构造函数创建txt文本，并且打开该文本
    // // Equality FSS test
    // for (uint64_t i = 1; i < roundsg; i = i + 5) {
    //   auto t_begin = std::chrono::high_resolution_clock::now();
    //   for (ag = 0; ag < i; ag++) {
    //     generateTreeEq(&fClient, &k0, &k1, ag, bg);
    //   }
    //   auto t_end = std::chrono::high_resolution_clock::now();
    //   OutFileG
    //       << std::chrono::duration<double, std::milli>(t_end - t_begin).count()
    //       << endl;
    // }
    // OutFileG.close();

    fssEvaluation();

    return 1;
}