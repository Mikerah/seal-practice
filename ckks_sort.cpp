#include <iostream>
#include "seal/seal.h"
#include "helpers.h"

using namespace std;
using namespace seal;

Ciphertext inv(EncryptionParameters parms, RelinKeys relin_keys, double scale, Decryptor* decryptor, Ciphertext x, int d) {

    SEALContext context(parms);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    Plaintext one_pt, two_pt;
    encoder.encode(1, scale, one_pt);
    encoder.encode(2, scale, two_pt);


    Ciphertext a_0, b_0;
    evaluator.negate_inplace(x);
    evaluator.add_plain(x, two_pt, a_0);
    evaluator.relinearize_inplace(a_0, relin_keys);
    evaluator.add_plain(x, one_pt, b_0);
    evaluator.relinearize_inplace(b_0, relin_keys);


    for (int i = 0; i < d; i++) {
        
        evaluator.square_inplace(b_0);
        evaluator.relinearize_inplace(b_0, relin_keys);
        evaluator.rescale_to_next_inplace(b_0);

        Plaintext b_0_plain;
        vector<double> b_0_vec;
        (*decryptor).decrypt(b_0, b_0_plain);
        encoder.decode(b_0_plain, b_0_vec);
        cout << "b_0: " << b_0_vec[0] << endl;

        Ciphertext tmp;

        evaluator.mod_switch_to_inplace(a_0, b_0.parms_id());
        /* cout << "a_0 scale: " << log2(a_0.scale()) << endl;
        cout << "b_0 scale: " << log2(b_0.scale()) << endl; */
        b_0.scale() = scale;

        evaluator.multiply(a_0, b_0, tmp);
        evaluator.relinearize_inplace(tmp, relin_keys);
        evaluator.rescale_to_next_inplace(tmp);

        Plaintext tmp_plain;
        vector<double> tmp_vec;
        (*decryptor).decrypt(tmp, tmp_plain);
        encoder.decode(tmp_plain, tmp_vec);
        cout << "tmp: " << tmp_vec[0] << endl;

        tmp.scale() = scale;
        evaluator.mod_switch_to_inplace(a_0, tmp.parms_id());
        evaluator.add_inplace(a_0, tmp);
        evaluator.relinearize_inplace(a_0, relin_keys); 

        Plaintext a_0_plain;
        vector<double> a_0_vec;
        (*decryptor).decrypt(a_0, a_0_plain);
        encoder.decode(a_0_plain, a_0_vec);
        cout << "a_0: " << a_0_vec[0] << endl;
    
    }

    return a_0;
}

void main_inv()
{
    // Create encryption parameters.
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // cout << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 60}));
    
    // parms.set_coeff_modulus(CoeffModulus::CKKSDefault(poly_modulus_degree));

    SEALContext context(parms);

    // Generate keys.
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

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
    encoder.encode(0.25, scale, plain2);

    // Encrypt the plaintexts.
    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);

    // Perform inv on ciphertexts.
    Ciphertext inv_05 = inv(parms, relin_keys, scale, &decryptor, cipher1, 5);
    Ciphertext inv_025 = inv(parms, relin_keys, scale, &decryptor, cipher2, 5);

    // Decrypt the result.
    Plaintext plain_result1, plain_result2;
    decryptor.decrypt(inv_05, plain_result1);
    decryptor.decrypt(inv_025, plain_result2);

    // Decode the result.
    vector<double> result1, result2;
    encoder.decode(plain_result1, result1);
    encoder.decode(plain_result2, result2);

    cout << "Actual result1: " << result1[0] << endl;
    //print_vector(result1);
    cout << "Expected result1: 2" << endl;

    cout << "Actual result1: " << result2[0] << endl;
    cout << "Expected result2: 4" << endl;

}
