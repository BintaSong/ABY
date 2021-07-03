#include "dtread.h"

// void encrypt_tree(string filename){
// 	DecTree tree;
// 	tree.read_from_file(filename);
//     std::cout << tree.num_attributes  << '\n';
// 	std::cout << tree.num_dec_nodes  << '\n';
// 	ss_real_tree(tree);
// }

void encrypt_tree(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing comparesharing, string filename){
	uint32_t keybitlen = seclvl.symbits;
	DecTree tree;
	tree.read_from_file(filename);
#ifdef DTREE_DEBUG
    std::cout << tree.num_attributes  << '\n';
	std::cout << tree.num_dec_nodes  << '\n';
#endif 
	ss_real_tree(tree);
}