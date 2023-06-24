#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

string uint64_to_hex_string(uint64_t value);

int main()
{
    // Create encryption parameters.
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(256);

    SEALContext context(parms);

    // Generate keys.
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Create an Evaluator instance.
    Evaluator evaluator(context);

    // Create an Encryptor instance.
    Encryptor encryptor(context, public_key);

    // Create an Decryptor instance.
    Decryptor decryptor(context, secret_key);

    // Encode two integers as plaintexts.
    uint64_t x = 2;
    uint64_t y = 3;
    Plaintext plain1(uint64_to_hex_string(x));
    Plaintext plain2(uint64_to_hex_string(y));

    // Encrypt the plaintexts.
    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);

    // Perform addition on ciphertexts.
    Ciphertext cipher_result;
    evaluator.add(cipher1, cipher2, cipher_result);

    // Decrypt the result.
    Plaintext plain_result;
    decryptor.decrypt(cipher_result, plain_result);

    cout << "Decrypted result: " << plain_result.to_string() << endl;

    return 0;
}

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}