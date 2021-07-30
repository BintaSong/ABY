#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <cstdlib>
#include <deque>
#include <stdio.h>
#include <vector>
using namespace std;
/*
*删除文本文件的空行
*
*/
int rm_BlankLine(string file){
    fstream targetFile("../../../../build/bin/log.txt",fstream::in | fstream::out);
    string line;//作为读取的每一行
    string temp;//作为缓存使用
    deque<string> noBlankLineQueue;//双向队列,只在队首和队尾操作时性能较好
        //判断文件是否打开
    if(!targetFile){
        cerr << "Can't Open File!" << endl;
        return EXIT_FAILURE;        
    }
    //记录文件开始位置
    auto StartPos = targetFile.tellp();
//循环读取判断文件的空行并放入队列
    while(getline(targetFile,line))
    {
        cout << targetFile.tellg() << endl;;    
        if(line.empty())
        {
            // cout << "此行为空" << endl; 
        }
        else
        {
            
            // cout << "上一行是空行" << endl;   
            noBlankLineQueue.push_back(line);
        }   
    }
    targetFile.close(); 
    //使用ofstream打开再关闭文件是为了清空源文件
    ofstream emptyFile(file);
    emptyFile.close();
    //重新打开文本文件
    fstream target(file,fstream::out | fstream::in);
    if(!target){
        cerr << "Can't Open File" << endl;
    }
    //获取队首和队尾
    auto begin = noBlankLineQueue.begin();
    auto end = noBlankLineQueue.end();
    //遍历双向队列中的元素
    //并写回文件
    while(begin != end){
        temp = *begin;
        cout << temp << endl;
        target << temp << endl; 
        ++begin;
    }
    target.close();
    return EXIT_SUCCESS;
}

void tokenize(const string& str, vector<string>& tokens) {
	tokens.clear();
	size_t prev = 0, pos;
    //if there is any " " [] \\ in str, it will return 1 //"string::npos"means find failed
    while ((pos = str.find_first_of(" \t " , prev)) != string::npos)
    {
        if (pos > prev)
            tokens.push_back(str.substr(prev, pos-prev));
        prev = pos+1;
    }
    if (prev < str.length())
        tokens.push_back(str.substr(prev, string::npos));
}

void read(string string_file){
    double online_time = 0;
    int sent_data = 0;
    int rcv_data = 0;
    const char* filename = string_file.c_str();
    ifstream file;
    file.open(filename);
#ifdef DTREE_DEBUG
    cout << filename << endl;
#endif 
    if (!file)  //条件成立，则说明文件打开出错
        cout << "open errors" << endl;

    string line;
    vector<string> tokens;
    vector<uint64_t>::iterator it;
    while (getline(file, line)){
        tokenize(line, tokens);

        if(tokens[0] == "Online" && tokens[1] == "="){
            //cout << stod(tokens[2].c_str()) << endl;
            online_time += stod(tokens[2].c_str());
        }
        else if(tokens[0] == "Online" && tokens[1] == "Sent"){
            sent_data += atoi(tokens[4].c_str());
            rcv_data += atoi(tokens[7].c_str());
        }
    }

// #ifdef READ_DEBUG
    cout << "Total online running time is " << online_time << "ms" << endl;
    cout << "Total sent data is " << sent_data/1024 << "KB" << endl;
    cout << "Total received data is " << rcv_data/1024 << "KB" << endl;
// #endif 
    file.close();
}
int main(){
    rm_BlankLine("destination.txt");
    read("destination.txt");
}