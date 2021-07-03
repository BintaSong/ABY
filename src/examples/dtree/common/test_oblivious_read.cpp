#include "test_oblivious_read.h"

//dot product by addition
void dotProductAdd(int tag, vector<ss_tuple_mz>& encryptedTreeV, mpz_class &r1, mpz_class &r2, mpz_class &r3){
    r1 = 0;
    r2 = 0;
    r3 = 0;
    vector<mpz_class> readResult1;
    vector<mpz_class> readResult2;
    //file path is according to exe's location
    ifstream readResultFile1("../../src/examples/dtree/fss/EvaluationResult1.txt");
    ifstream readResultFile2("../../src/examples/dtree/fss/EvaluationResult2.txt");
    if (!readResultFile1.is_open()) {
      cout << "Could not open the file: EvaluationResult1" << endl;
      return;
    }
    if (!readResultFile2.is_open()) {
      cout << "Could not open the file: EvaluationResult2" << endl;
      return;
    }
    while (!readResultFile1.eof()) {
        mpz_class tmp;
        readResultFile1 >> tmp;
        readResult1.push_back(tmp);
    }
    while (!readResultFile2.eof()) {
        mpz_class tmp;
        readResultFile2 >> tmp;
        readResult2.push_back(tmp);
    }
    //client
    if(tag == 0){
        int count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r1 = *(it->plain.data()) * readResult1[count] + r1;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r2 = *(it->plain.data() + 1) * readResult1[count] + r2;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r3 = *(it->plain.data() + 2) * readResult1[count] + r3;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
    }else if(tag == 1){//provider
        int count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r1 = *(it->plain.data()) * readResult2[count] + r1;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r2 = *(it->plain.data() + 1) * readResult2[count] + r2;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r3 = *(it->plain.data() + 2) * readResult2[count] + r3;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
    }
    readResultFile1.close();
    readResultFile2.close();
}

//dot product by xor
void dotProductXor(int tag, vector<ss_tuple_mz>& encryptedTreeV, mpz_class &r1, mpz_class &r2, mpz_class &r3){
    r1 = 0;
    r2 = 0;
    r3 = 0;
    vector<mpz_class> readResult1;
    vector<mpz_class> readResult2;
    //file path is according to exe's location
    ifstream readResultFile1("../../src/examples/dtree/fss/EvaluationResult1.txt");
    ifstream readResultFile2("../../src/examples/dtree/fss/EvaluationResult2.txt");
    if (!readResultFile1.is_open()) {
      cout << "Could not open the file: EvaluationResult1" << endl;
      return;
    }
    if (!readResultFile2.is_open()) {
      cout << "Could not open the file: EvaluationResult2" << endl;
      return;
    }
    while (!readResultFile1.eof()) {
        mpz_class tmp;
        readResultFile1 >> tmp;
        readResult1.push_back(tmp);
    }
    while (!readResultFile2.eof()) {
        mpz_class tmp;
        readResultFile2 >> tmp;
        readResult2.push_back(tmp);
    }
    //client
    if(tag == 0){
        int count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r1 = *(it->plain.data()) * readResult1[count] ^ r1;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r2 = *(it->plain.data() + 1) * readResult1[count] ^ r2;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r3 = *(it->plain.data() + 2) * readResult1[count] ^ r3;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
    }else if(tag == 1){//provider
        int count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r1 = *(it->plain.data()) * readResult2[count] ^ r1;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r2 = *(it->plain.data() + 1) * readResult2[count] ^ r2;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<ss_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r3 = *(it->plain.data() + 2) * readResult2[count] ^ r3;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
    }
    readResultFile1.close();
    readResultFile2.close();
}


//dot product by xor
void readTreeFSS(int tag, vector<node_tuple_mz>& encryptedTreeV, mpz_class &r1, mpz_class &r2, mpz_class &r3){
    r1 = 0;
    r2 = 0;
    r3 = 0;
    vector<mpz_class> readResult1;
    vector<mpz_class> readResult2;
    //file path is according to exe's location
    ifstream readResultFile1("../../src/examples/dtree/fss/EvaluationResult1.txt");
    ifstream readResultFile2("../../src/examples/dtree/fss/EvaluationResult2.txt");
    if (!readResultFile1.is_open()) {
      cout << "Could not open the file: EvaluationResult1" << endl;
      return;
    }
    if (!readResultFile2.is_open()) {
      cout << "Could not open the file: EvaluationResult2" << endl;
      return;
    }
    while (!readResultFile1.eof()) {
        mpz_class tmp;
        readResultFile1 >> tmp;
        readResult1.push_back(tmp);
    }
    while (!readResultFile2.eof()) {
        mpz_class tmp;
        readResultFile2 >> tmp;
        readResult2.push_back(tmp);
    }
    //client
    if(tag == 0){
        int count = 0;
        for (vector<node_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r1 = *(it->plain.data()) * readResult1[count] ^ r1;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<node_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r2 = *(it->plain.data() + 1) * readResult1[count] ^ r2;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<node_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r3 = *(it->plain.data() + 2) * readResult1[count] ^ r3;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
    }else if(tag == 1){//provider
        int count = 0;
        for (vector<node_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r1 = *(it->plain.data()) * readResult2[count] ^ r1;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<node_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r2 = *(it->plain.data() + 1) * readResult2[count] ^ r2;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
        count = 0;
        for (vector<node_tuple_mz>::iterator it = encryptedTreeV.begin();
             it < encryptedTreeV.end(); it++, count++) {
          r3 = *(it->plain.data() + 2) * readResult2[count] ^ r3;
          // es_xor_class_plain(output, *(it->plain.data()));
        }
    }
    readResultFile1.close();
    readResultFile2.close();
}


void readFeatureFSS(node_tuple_mz encryptedFeature, int num, uint64_t shift, uint64_t & attrValue, string fssKeyFile){
    int a = ceil(log(num));
    cout << "a is " << a << endl;
    int b = pow(2, a);
    cout << "b is " << b << endl;
    vector<uint64_t> readResult;
    ifstream readFileResult(fssKeyFile);
    if (!readFileResult.is_open()) {
      cout << "Could not open the file: " << fssKeyFile << endl;
      return;
    }
    int i;
    while (!readFileResult.eof() && i < b) {
        uint64_t tmp;
        readFileResult >> tmp;
        readResult.push_back(tmp);
        i++;
    }
    //填充成2^a。
    for(; i < b; i++){
        readResult[i] = 0;
    }
}


