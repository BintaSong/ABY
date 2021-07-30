#include "datawash.h"
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