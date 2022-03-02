#include <iostream>
#include "seal/seal.h"

using namespace seal;

int main() {

    //Prepare parameters
    EncryptionParameters parms(scheme_type::bfv);

    //    Larger poly_modulus_degree makes ciphertext sizes larger and all operations
    //    slower, but enables more complicated encrypted computations. Recommended
    //    values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
    //    to go beyond this range.

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    std::cout << "Hello, World!" << std::endl;
    return 0;
}
