#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void main_arrays()
{
    // Create encryption parameters.
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

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

    // Create CKKSEncoder instance
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Vector of float values.
    vector<double> input_data = {0.5, 1.3, 0.7, 2.2, 0.9};

    // Vector to hold plaintexts and ciphertexts.
    vector<Plaintext> plain_data(input_data.size());
    vector<Ciphertext> cipher_data(input_data.size());

    // Encode and encrypt the data.
    for (size_t i = 0; i < input_data.size(); i++) {
        encoder.encode(input_data[i], scale, plain_data[i]);
        encryptor.encrypt(plain_data[i], cipher_data[i]);
    }

    // Perform addition on ciphertexts.
    Ciphertext cipher_result = cipher_data[0];
    for (size_t i = 1; i < cipher_data.size(); i++) {
        evaluator.add_inplace(cipher_result, cipher_data[i]);
    }

    // Decrypt the result.
    Plaintext plain_result;
    decryptor.decrypt(cipher_result, plain_result);

    // Decode the result.
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Decrypted result: " << result[0] << endl;

}
