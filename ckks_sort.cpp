#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

Ciphertext inv(SEALContext *context, RelinKeys relin_keys, double scale, Plaintext one_pt, Plaintext two_pt, Ciphertext x, int d) {
    Evaluator evaluator(*context);
    //CKKSEncoder encoder(*context);
    //CKKSEncoder encoder(context);
    
    /*
    Plaintext one_pt, two_pt;
    encoder.encode(1.0, scale, one_pt);
    encoder.encode(2.0, scale, two_pt);
    Ciphertext one_ct, two_ct;
    encryptor.encrypt(one_pt, one_ct);
    encryptor.encrypt(two_pt, two_ct);
    */

    Ciphertext a_0, b_0;
    evaluator.negate_inplace(x);
    evaluator.add_plain(x, two_pt, a_0);
    evaluator.add_plain(x, one_pt, b_0);

    Ciphertext *tmp_a = &a_0;
    Ciphertext *tmp_b = &b_0;

    for (int i = 0; i < d; i++) {
        evaluator.square(*tmp_b, *tmp_b);
        evaluator.relinearize_inplace(*tmp_b, relin_keys);
        evaluator.rescale_to_next(*tmp_b, *tmp_b);

        Ciphertext tmp;

        evaluator.mod_switch_to_inplace(one_pt, (*tmp_b).parms_id());
        evaluator.add_plain(*tmp_b, one_pt, tmp);
        /* evaluator.rescale_to_next(tmp, tmp);
        cout << tmp.scale() << endl;
        cout << (*tmp_a).scale() << endl; */

        /* evaluator.multiply(*tmp_a, tmp, *tmp_a);
        evaluator.relinearize_inplace(*tmp_a, relin_keys);
        evaluator.rescale_to_next(*tmp_a, *tmp_a); */
    }

    return *tmp_a;
}

void main_inv()
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
    Plaintext plain1, plain2, one_pt, two_pt;
    encoder.encode(0.5, scale, plain1);
    encoder.encode(4.0, scale, plain2);
    encoder.encode(1.0, scale, one_pt);
    encoder.encode(2.0, scale, two_pt);

    // Encrypt the plaintexts.
    Ciphertext cipher1, cipher2, one_ct, two_ct;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);
    //encryptor.encrypt(one_pt, one_ct);
    //encryptor.encrypt(two_pt, two_ct);

    // Perform inv on ciphertexts.
    Ciphertext inv_05 = inv(&context, relin_keys, scale, one_pt, two_pt, cipher1, 5);
    Ciphertext inv_4 = inv(&context, relin_keys, scale, one_pt, two_pt, cipher2, 5);

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
    cout << "Expected result2: 0.25";

}
