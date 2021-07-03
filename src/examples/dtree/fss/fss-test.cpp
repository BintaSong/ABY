#include <chrono>//时间头文件
#include <fstream>//写文件
#include "fss-common.h"
#include "fss-server.h"
#include "fss-client.h"
#include <iostream>

using namespace std;

void fssEvaluation(){
    uint64_t a = 3;//64 bits unsigned long
    uint64_t b = 1;
    Fss fClient, fServer;
    ServerKeyEq k0;
    ServerKeyEq k1;
    // Initialize client, use 10 bits in domain as example
    initializeClient(&fClient, 10, 2); 
    
    // Equality FSS test
    //cout << "****Equality FSS test****" << endl;
    generateTreeEq(&fClient, &k0, &k1, a, b);

    initializeServer(&fServer, &fClient);
    mpz_class ans0, ans1, fin;
    bool tr;
    //terminal test
    ans0 = evaluateEq(&fServer, &k0, 719, tr);
    ans1 = evaluateEq(&fServer, &k1, 719, tr);
    cout << ans0 << "\t" << tr << endl;
    cout << ans1 << "\t" << tr << endl;
    //write to files
    ofstream OutFile1("ZeroOrOne0.txt"); //利用构造函数创建txt文本，并且打开该文本
    ofstream OutFile2("ZeroOrOne1.txt"); 
    //bool tr;
    for(int i = 1; i < 100; i++){
      ans0 = evaluateEq(&fServer, &k0, i, tr);
      OutFile1 << tr << endl;
      ans1 = evaluateEq(&fServer, &k1, i, tr);
      OutFile2 << tr << endl;
    }
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