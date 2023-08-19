#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main_conditional_select() {
    // Set up encryption parameters.
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    SEALContext context(parms);
    
    // Generate keys.
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Set up encoder and encryptor.
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    
    // Scale.
    double scale = pow(2.0, 40);

    // Conditional variables.
    vector<double> condition{ 0.0, 1.0 };
    vector<double> x_values{ 2.0, 3.0 };
    vector<double> y_values{ 4.0, 5.0 };

    // Encode and encrypt.
    Plaintext condition_pt, x_pt, y_pt;
    encoder.encode(condition, scale, condition_pt);
    encoder.encode(x_values, scale, x_pt);
    encoder.encode(y_values, scale, y_pt);

    Ciphertext condition_enc, x_enc, y_enc;
    encryptor.encrypt(condition_pt, condition_enc);
    encryptor.encrypt(x_pt, x_enc);
    encryptor.encrypt(y_pt, y_enc);

    // Evaluate: result_enc = condition_enc * x_enc + (1 - condition_enc) * y_enc.
    Ciphertext result_enc, ones_enc;
    evaluator.multiply(condition_enc, x_enc, result_enc);
    evaluator.negate(condition_enc, ones_enc);
    Plaintext tmp;
    encoder.encode(vector<double>(2, 1.0), scale, tmp);
    evaluator.add_plain_inplace(ones_enc, tmp);
    evaluator.multiply_inplace(ones_enc, y_enc);
    evaluator.add_inplace(result_enc, ones_enc);

    // Decrypt and decode.
    Plaintext result_pt;
    decryptor.decrypt(result_enc, result_pt);
    vector<double> result;
    encoder.decode(result_pt, result);
    
    // Output results.
    cout << "Result: " << result[0] << ", " << result[1] << endl;

    return 0;
}
