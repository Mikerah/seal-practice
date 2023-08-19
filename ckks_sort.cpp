#include <iostream>
#include "seal/seal.h"
#include "helpers.h"

using namespace std;
using namespace seal;

Ciphertext inv(EncryptionParameters parms, RelinKeys relin_keys, double scale, Ciphertext x, int d) {

    SEALContext context(parms);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    Plaintext one_pt, two_pt;
    encoder.encode(1.0, scale, one_pt);
    encoder.encode(2.0, scale, two_pt);


    Ciphertext a_0, b_0;
    evaluator.negate_inplace(x);
    evaluator.add_plain(x, two_pt, a_0);
    evaluator.add_plain(x, one_pt, b_0);
    //evaluator.rescale_to_next_inplace(a_0);
    //evaluator.rescale_to_next_inplace(b_0);

    Ciphertext *tmp_a = &a_0;
    Ciphertext *tmp_b = &b_0;

    for (int i = 0; i < d; i++) {
        evaluator.square(*tmp_b, *tmp_b);
        evaluator.relinearize_inplace(*tmp_b, relin_keys);
        evaluator.rescale_to_next_inplace(*tmp_b);

        Ciphertext tmp;

        evaluator.mod_switch_to_inplace(*tmp_a, (*tmp_b).parms_id());
        evaluator.multiply(*tmp_b, *tmp_a, tmp);
        evaluator.relinearize_inplace(tmp, relin_keys);
        evaluator.rescale_to_next_inplace(tmp);

        
        //(*tmp_a).scale() = pow(2.0, 40);
        //tmp.scale() = pow(2.0, 40);

        /*
        cout << "Scale of tmp_b: " << log2((*tmp_b).scale()) << endl;
        cout << "Scale of tmp_a: " << log2((*tmp_a).scale()) << endl;
        cout << "Scale of tmp: " << log2(tmp.scale()) << endl;
    
        cout << "Parms of tmp_b: " << (*tmp_b).parms_id() << endl;
        cout << "Parms of tmp_a: " << (*tmp_a).parms_id() << endl;
        cout << "Parms of tmp: " << tmp.parms_id() << endl;
        */

        tmp.scale() = pow(2.0, 40);
        evaluator.mod_switch_to_inplace(*tmp_a, tmp.parms_id());
        evaluator.add_inplace(*tmp_a, tmp);
        evaluator.relinearize_inplace(*tmp_a, relin_keys);
    }

    return *tmp_a;
}

void main_inv()
{
    // Create encryption parameters.
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // cout << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60, 60, 60, 60, 50}));
    
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
    encoder.encode(4.0, scale, plain2);

    // Encrypt the plaintexts.
    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);

    // Perform inv on ciphertexts.
    Ciphertext inv_05 = inv(parms, relin_keys, scale, cipher1, 5);
    Ciphertext inv_4 = inv(parms, relin_keys, scale, cipher2, 5);

    // Decrypt the result.
    Plaintext plain_result1, plain_result2;
    decryptor.decrypt(inv_05, plain_result1);
    decryptor.decrypt(inv_4, plain_result2);

    // Decode the result.
    vector<double> result1, result2;
    encoder.decode(plain_result1, result1);
    encoder.decode(plain_result2, result2);

    cout << "Actual result1: " << result1[0] << endl;
    cout << "Expected result1: 2" << endl;

    cout << "Actual result2: " << result2[0] << endl;
    cout << "Expected result2: 0.25" << endl;

}
