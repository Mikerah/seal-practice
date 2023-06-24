#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void main_simple_floating_point()
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

    // Encode two floats as plaintexts.
    Plaintext plain1, plain2;
    encoder.encode(0.5, scale, plain1);
    encoder.encode(1.3, scale, plain2);

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

    // Decode the result.
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Decrypted result: " << result[0] << endl;

}
