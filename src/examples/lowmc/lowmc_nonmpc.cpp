/**
 \file 		lowmc.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		LowMC implementation.
 */

#include "common/LowMC.h"
#include <iostream>

int main(int argc, char** argv) {
	LowMC cipher(0x0304);
	//cipher.print_matrices();
    // block m = 0b101010101111, c;
    block m = 0x6, c;
    std::cout << "Plaintext:" << std::endl;
    std::cout << m << std::endl;


	cipher.save_matrices();
	//cipher.print_matrices();

    c = cipher.encrypt( m );
    std::cout << "\nCiphertext:" << std::endl;
    std::cout<< c <<std::endl;

    m = cipher.decrypt( c );
    std::cout << "\nEncryption followed by decryption of plaintext:" << std::endl;
    std::cout<< m <<std::endl;

	
	return 0;
}
