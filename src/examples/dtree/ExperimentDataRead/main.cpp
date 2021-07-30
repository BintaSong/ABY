#include "datawash.h"
#include "read.h"

int main(){
    rm_BlankLine("destination.txt"); 
    string filename = "destination.txt";
    read(filename);
    return 0;
}
