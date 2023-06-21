#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main()
{
    // Create encryption parameters.
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(256);

    auto context = SEALContext::Create(parms);

    // Generate keys.
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    // Create an Evaluator instance.
    Evaluator evaluator(context);

    // Create an Encryptor instance.
    Encryptor encryptor(context, public_key);

    // Create an Decryptor instance.
    Decryptor decryptor(context, secret_key);

    // Encode two integers as plaintexts.
    Plaintext plain1 = "2";
    Plaintext plain2 = "3";

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
