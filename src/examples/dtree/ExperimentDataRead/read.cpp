#include "read.h"

/**
 * Takes a string in the Format "i i i ..." separated by ' '
 * @param str the string to tokenize
 * @param tokens the result vector of wire id
 */
void tokenize(const std::string& str, std::vector<string>& tokens) {
	tokens.clear();
	std::size_t prev = 0, pos;
    //if there is any " " [] \\ in str, it will return 1 //"string::npos"means find failed
    while ((pos = str.find_first_of(" \t " , prev)) != std::string::npos)
    {
        if (pos > prev)
            tokens.push_back(str.substr(prev, pos-prev));
        prev = pos+1;
    }
    if (prev < str.length())
        tokens.push_back(str.substr(prev, std::string::npos));
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
