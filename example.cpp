#include "psu.h"
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <cassert>

typedef std::chrono::high_resolution_clock Time;
typedef decltype(std::chrono::high_resolution_clock::now()) Timepoint;
typedef long long Duration;
typedef std::chrono::milliseconds ms;

namespace
{
    void log_time(std::stringstream &ss,
                  std::chrono::time_point<std::chrono::high_resolution_clock> start,
                  std::chrono::time_point<std::chrono::high_resolution_clock> end,
                  bool last = false)
    {
        ss << std::chrono::duration_cast<ms>(end - start).count();
        if (!last)
            ss << ",";
    }
} // namespace

void heco();

void naive();

int main()
{
    std::cout << "We will compute the set union between two sets (of the same size) encrypted under the same key:" << std::endl;
    const size_t SET_SIZE = 128;
    assert(pow(2.0, log2(SET_SIZE)) == SET_SIZE && "SET SIZE MUST BE A POWER OF TWO");

    std::stringstream ss_time;

    std::cout << "The output party (A) generates the keys and publishes the public key." << std::endl;
    class A
    {
    public:
        std::shared_ptr<seal::EncryptionParameters> parms;
        std::shared_ptr<seal::PublicKey> public_key;
        std::shared_ptr<seal::BatchEncoder> encoder;
        std::shared_ptr<seal::SEALContext> context;
        std::shared_ptr<seal::Encryptor> encryptor;
        std::shared_ptr<seal::Evaluator> evaluator;
        std::shared_ptr<seal::RelinKeys> relin_keys;
        std::shared_ptr<seal::GaloisKeys> galois_keys;

        // Initialization
        A()
        {
            // Generate the secret set of 24 bit numbers (zero not allowed!)
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(1, 1 << 23);
            for (size_t i = 0; i < SET_SIZE; ++i)
            {
                set.insert(distrib(gen));
            }

            // Parameter selection
            parms = std::make_shared<seal::EncryptionParameters>(seal::scheme_type::bfv);
            size_t poly_modulus_degree = SET_SIZE * SET_SIZE;
            parms->set_poly_modulus_degree(poly_modulus_degree);
            parms->set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
            parms->set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
            context = std::make_shared<seal::SEALContext>(*parms);

            // Private part of KeyGen
            keygen = std::make_unique<seal::KeyGenerator>(*context);
            secret_key = std::make_unique<seal::SecretKey>(keygen->secret_key());
            decryptor = std::make_unique<seal::Decryptor>(*context, *secret_key);

            // Public Keys
            public_key = std::make_shared<seal::PublicKey>();
            keygen->create_public_key(*public_key);
            encoder = std::make_shared<seal::BatchEncoder>(*context);
            encryptor = std::make_shared<seal::Encryptor>(*context, *public_key);
            evaluator = std::make_shared<seal::Evaluator>(*context);
            relin_keys = std::make_shared<seal::RelinKeys>();
            keygen->create_relin_keys(*relin_keys);
            galois_keys = std::make_shared<seal::GaloisKeys>();
            keygen->create_galois_keys(*galois_keys);
        };

        psu::encrypted_identifiers encrypt_set()
        {
            return psu::encrypt_set_a(set, *encoder, *encryptor);
        }

        /// public only for testing!
        std::vector<uint64_t> decrypt(seal::Ciphertext &ctxt)
        {
            seal::Plaintext ptxt;
            decryptor->decrypt(ctxt, ptxt);
            std::vector<uint64_t> v;
            encoder->decode(ptxt, v);
            return v;
        }

        /// public only for testing!
        std::set<uint32_t> get_set_for_testing()
        {
            return set;
        }

    private:
        std::unique_ptr<seal::KeyGenerator> keygen;
        std::unique_ptr<seal::SecretKey> secret_key;
        std::unique_ptr<seal::Decryptor> decryptor;

        std::set<uint32_t> set;
    };

    /// Instance of the output party
    A a;

    /// Encrypt a's set
    auto input_a = a.encrypt_set();

    std::cout << "The second party (B) only provides an encrypted input. This is sent to the third-party compute server." << std::endl;

    class B
    {
    public:
        // Initialization
        B()
        {
            // Generate the secret set of 24 bit numbers (zero not allowed!)
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(1, 1 << 23);
            for (size_t i = 0; i < SET_SIZE; ++i)
            {
                set.insert(distrib(gen));
            }
        }

        psu::encrypted_identifiers encrypt_set(const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
        {
            return psu::encrypt_set_b(set, encoder, encryptor);
        }

        /// public only for testing!
        std::set<uint32_t> get_set_for_testing()
        {
            return set;
        }

    private:
        std::set<uint32_t> set;
    };

    /// Instance of the input party
    B b;

    /// Encrypt b's set
    auto input_b = b.encrypt_set(*a.encoder, *a.encryptor);
    seal::Plaintext p_a_data;
    a.encoder->encode(std::vector<uint64_t>(SET_SIZE * SET_SIZE, 42), p_a_data);
    seal::Ciphertext a_data;
    a.encryptor->encrypt(p_a_data, a_data);

    seal::Plaintext p_b_data;
    a.encoder->encode(std::vector<uint64_t>(SET_SIZE * SET_SIZE, 24), p_b_data);
    seal::Ciphertext b_data;
    a.encryptor->encrypt(p_b_data, b_data);

    std::cout << "Now the third party (C) computes the private set union and returns the result to A:" << std::endl;

    Timepoint t_start = Time::now();
    auto bits = psu::compute_b_minus_a_bools(input_a, input_b, a_data, b_data, SET_SIZE, *a.encoder, *a.encryptor, *a.context, *a.relin_keys, *a.galois_keys, *a.evaluator);
    Timepoint t_end = Time::now();
    log_time(ss_time, t_start, t_end, true);

    std::cout << "Now we'll verify the result:" << std::endl;

    // Decrypt the result
    auto bits_dec = a.decrypt(bits);

    // Get the "real" sets
    auto set_a = a.get_set_for_testing();
    auto set_b = b.get_set_for_testing();

    // Convert bits to an actual union:
    auto result = psu::bits_to_set(set_a, set_b, bits_dec);
    int result_sum = 0;
    for (auto &e : result)
    {
        result_sum += e;
    }

    // Compute "correct" union
    std::set<uint32_t> actual_union;
    std::set_union(set_a.begin(), set_a.end(), set_b.begin(), set_b.end(),
                   std::inserter(actual_union, actual_union.begin()));

    // compute the sum
    int actual_sum = 0;
    for (auto &e : actual_union)
    {
        actual_sum += e;
    }

    if (result_sum == actual_sum)
    {
        std::cout << "The result is correct! Yay!" << std::endl;
    }
    else
    {
        std::cout << "Oops..something went wrong :(" << std::endl;

        std::cout << "Set a:" << std::endl;
        for (auto &x : set_a)
        {
            std::cout << x << " ";
        }
        std::cout << std::endl;

        std::cout << "Set b:" << std::endl;
        for (auto &x : set_b)
        {
            std::cout << x << " ";
        }
        std::cout << std::endl;

        std::cout << "Actual union:" << std::endl;
        for (auto &x : actual_union)
        {
            std::cout << x << " ";
        }
        std::cout << std::endl;

        std::cout << "Result:" << std::endl;
        for (auto &x : result)
        {
            std::cout << x << " ";
        }
        std::cout << std::endl;
    }

    std::cout << "Time taken: " << ss_time.str() << " ms" << std::endl;

    heco();
    naive();
}

void heco()
{
    std::stringstream ss_time;

    std::cout << "Now, we will compute the heco approach" << std::endl;

    const size_t SET_SIZE = 128;

    std::shared_ptr<seal::EncryptionParameters> parms;
    std::shared_ptr<seal::PublicKey> public_key;
    std::shared_ptr<seal::BatchEncoder> encoder;
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::Encryptor> encryptor;
    std::shared_ptr<seal::Evaluator> evaluator;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;
    std::unique_ptr<seal::KeyGenerator> keygen;
    std::unique_ptr<seal::SecretKey> secret_key;
    std::unique_ptr<seal::Decryptor> decryptor;

    // Parameter selection
    parms = std::make_shared<seal::EncryptionParameters>(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms->set_poly_modulus_degree(poly_modulus_degree);
    parms->set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms->set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
    context = std::make_shared<seal::SEALContext>(*parms);

    // Private part of KeyGen
    keygen = std::make_unique<seal::KeyGenerator>(*context);
    secret_key = std::make_unique<seal::SecretKey>(keygen->secret_key());
    decryptor = std::make_unique<seal::Decryptor>(*context, *secret_key);

    // Public Keys
    public_key = std::make_shared<seal::PublicKey>();
    keygen->create_public_key(*public_key);
    encoder = std::make_shared<seal::BatchEncoder>(*context);
    encryptor = std::make_shared<seal::Encryptor>(*context, *public_key);
    evaluator = std::make_shared<seal::Evaluator>(*context);
    relin_keys = std::make_shared<seal::RelinKeys>();
    keygen->create_relin_keys(*relin_keys);
    galois_keys = std::make_shared<seal::GaloisKeys>();
    keygen->create_galois_keys(*galois_keys);

    seal::Ciphertext a_id;
    seal::Ciphertext a_data;
    seal::Ciphertext b_id;
    seal::Ciphertext b_data;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 10000);

    seal::Plaintext p;
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen) % 2), p);
    encryptor->encrypt(p, a_id);
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen) % 2), p);
    encryptor->encrypt(p, b_id);
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen)), p);
    encryptor->encrypt(p, a_data);
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen)), p);
    encryptor->encrypt(p, b_data);

    Timepoint t_start = Time::now();

    // def encryptedPSU(a_id: Tensor[128, 8, sf64], a_data: Tensor[128, sf64],
    //                b_id: Tensor[128, 8, sf64], b_data: Tensor[128, sf64]) -> sf64:
    seal::Plaintext p_one;
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, 1), p_one);
    seal::Ciphertext one;
    encryptor->encrypt(p_one, one);

    // compute the sum over A
    seal::Plaintext p_zero;
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, 0), p_zero);
    seal::Ciphertext rot_a;
    seal::Ciphertext sum_a = a_data;
    for (size_t i = SET_SIZE / 2; i > 0; i /= 2)
    {
        evaluator->rotate_rows(sum_a, i, *galois_keys, rot_a);
        evaluator->add_inplace(sum_a, rot_a);
    }

    // NOW WE HAVE O(n) nequal computations  instead of O(n^2)
    // Each of them uses O(1) instead of O(k) to compute the xor
    // Each of them uses O(log(k)) instead of O(k) mults to compute equal
    std::vector<seal::Ciphertext> nequals(SET_SIZE);
    for (size_t i = 1; i < SET_SIZE; ++i)
    {
        // compute a_id[j] != b_id[j-i*8 % 4] for each iteration
        // Note that the rotation is by 8 x the offset because of the column-major encoding!
        // compute xor
        // %7 = fhe.rotate(%b_id) by -i*8 : <8 x i16>
        seal::Ciphertext x;
        evaluator->rotate_rows(a_id, -i * 8, *galois_keys, x);
        // %8 = fhe.sub(%a_id, %7) : (!fhe.batched_secret<8 x i16>, !fhe.batched_secret<8 x i16>) -> !fhe.batched_secret<8 x i16>
        evaluator->sub(a_id, x, x);
        // %9 = fhe.multiply(%8, %8) : (!fhe.batched_secret<8 x i16>, !fhe.batched_secret<8 x i16>) -> !fhe.batched_secret<8 x i16>
        evaluator->square_inplace(x);
        evaluator->relinearize_inplace(x, *relin_keys);
        // %10 = fhe.sub(%cst, %9) : (!fhe.batched_secret<8 x i16>, !fhe.batched_secret<8 x i16>) -> !fhe.batched_secret<8 x i16>
        evaluator->sub(one, x, x);
        // // update nequal: multiply all bits, then negate
        // %11 = fhe.rotate(%10) by 1 : <8 x i16>
        // %12 = fhe.multiply(%10, %11) : (!fhe.batched_secret<8 x i16>, !fhe.batched_secret<8 x i16>) -> !fhe.batched_secret<8 x i16>
        seal::Ciphertext equal = one;
        seal::Ciphertext rot;
        for (size_t i = 8 / 2; i > 0; i /= 2)
        {
            evaluator->rotate_columns(x, *galois_keys, rot);
            evaluator->multiply_inplace(equal, rot);
            evaluator->relinearize_inplace(equal, *relin_keys);
        }
        // %13 = fhe.sub(%cst, %12) : (!fhe.batched_secret<8 x i16>, !fhe.batched_secret<8 x i16>) -> !fhe.batched_secret<8 x i16>
        evaluator->sub(one, equal, nequals[i]);
    }

    // Now we compute O(n) unique * b[i], each sadly using O(n) rotates rather than the ideal O(1)
    // This also uses O(n*n) multiplications, since
    std::vector<seal::Ciphertext> uniques_times_bs;
    for (size_t i = 1; i < SET_SIZE; ++i)
    {
        std::vector<seal::Ciphertext> operands;
        operands.push_back(b_data);
        for (size_t j = 1; j < SET_SIZE; ++j)
        {
            seal::Ciphertext rot;
            evaluator->rotate_rows(nequals[j], -j * 8, *galois_keys, rot);
            operands.push_back(rot);
        }
        seal::Ciphertext product;
        evaluator->multiply_many(operands, *relin_keys, product);
        uniques_times_bs.push_back(product);
    }

    // the final sum uses O(log n) rotations //TODO: Nope, more like n!
    // running sum of loop (unique * b[i]) + sum of a[i] from before
    std::vector<seal::Ciphertext> operands;
    seal::Ciphertext rot_sum_a;
    evaluator->rotate_rows(sum_a, -7, *galois_keys, rot_sum_a); // TODO is -k + 1 correct offset?
    operands.push_back(rot_sum_a);

    for (size_t i = 0; i < SET_SIZE - 1; ++i)
    {
        // TODO: figure out what eaxctly we should rotate which one by!
        //  Not sure if mapping is actually this direct  between i and offset
        seal::Ciphertext rot;
        evaluator->rotate_rows(uniques_times_bs[i], i + 1, *galois_keys, rot);
        operands.push_back(rot);
    }
    seal::Ciphertext result;
    evaluator->add_many(operands, result);

    Timepoint t_end = Time::now();
    log_time(ss_time, t_start, t_end, true);
    std::cout << "Time taken:  " << ss_time.str() << " ms" << std::endl;

    // We will compute the set union between two sets (of the same size) encrypted under the same key:
    // The output party (A) generates the keys and publishes the public key.
    // The second party (B) only provides an encrypted input. This is sent to the third-party compute server.
    // Now the third party (C) computes the private set union and returns the result to A:
    // Now we'll verify the result:
    // The result is correct! Yay!
    // Time taken: 1341 ms
    // Now, we will compute the heco approach
    // Time taken:  57732 ms
}

void naive()
{
    std::stringstream ss_time;

    std::cout << "Now, we will compute the naive approach" << std::endl;

    const size_t SET_SIZE = 128;

    std::shared_ptr<seal::EncryptionParameters> parms;
    std::shared_ptr<seal::PublicKey> public_key;
    std::shared_ptr<seal::BatchEncoder> encoder;
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::Encryptor> encryptor;
    std::shared_ptr<seal::Evaluator> evaluator;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;
    std::unique_ptr<seal::KeyGenerator> keygen;
    std::unique_ptr<seal::SecretKey> secret_key;
    std::unique_ptr<seal::Decryptor> decryptor;

    // Parameter selection
    parms = std::make_shared<seal::EncryptionParameters>(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms->set_poly_modulus_degree(poly_modulus_degree);
    parms->set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms->set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
    context = std::make_shared<seal::SEALContext>(*parms);

    // Private part of KeyGen
    keygen = std::make_unique<seal::KeyGenerator>(*context);
    secret_key = std::make_unique<seal::SecretKey>(keygen->secret_key());
    decryptor = std::make_unique<seal::Decryptor>(*context, *secret_key);

    // Public Keys
    public_key = std::make_shared<seal::PublicKey>();
    keygen->create_public_key(*public_key);
    encoder = std::make_shared<seal::BatchEncoder>(*context);
    encryptor = std::make_shared<seal::Encryptor>(*context, *public_key);
    evaluator = std::make_shared<seal::Evaluator>(*context);
    relin_keys = std::make_shared<seal::RelinKeys>();
    keygen->create_relin_keys(*relin_keys);
    galois_keys = std::make_shared<seal::GaloisKeys>();
    keygen->create_galois_keys(*galois_keys);

    std::vector<seal::Ciphertext> a_id(128 * 8);
    std::vector<seal::Ciphertext> a_data(128);
    std::vector<seal::Ciphertext> b_id(128 * 8);
    std::vector<seal::Ciphertext> b_data(128);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 10000);

    for (auto &c : a_id)
    {
        seal::Plaintext p;
        encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen) % 2), p);
        encryptor->encrypt(p, c);
    }

    for (auto &c : b_id)
    {
        seal::Plaintext p;
        encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen) % 2), p);
        encryptor->encrypt(p, c);
    }

    for (auto &c : a_data)
    {
        seal::Plaintext p;
        encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen)), p);
        encryptor->encrypt(p, c);
    }

    for (auto &c : b_data)
    {
        seal::Plaintext p;
        encoder->encode(std::vector<uint64_t>(poly_modulus_degree, distrib(gen)), p);
        encryptor->encrypt(p, c);
    }

    Timepoint t_start = Time::now();

    // def encryptedPSU(a_id: Tensor[128, 8, sf64], a_data: Tensor[128, sf64],
    //                b_id: Tensor[128, 8, sf64], b_data: Tensor[128, sf64]) -> sf64:
    seal::Plaintext p_one;
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, 1), p_one);
    seal::Ciphertext one;

    //   sum: sf64 = 0
    //   for i in range(0, 128):
    //       sum = sum + a_data[i]
    seal::Plaintext p_zero;
    encoder->encode(std::vector<uint64_t>(poly_modulus_degree, 0), p_zero);
    seal::Ciphertext sum;
    encryptor->encrypt(p_zero, sum);
    for (auto &a : a_data)
    {
        evaluator->add_inplace(sum, a);
    }

    //  for i in range(0, 128):
    for (size_t i = 0; i < 128; ++i)
    {
        // unique: sf64 = 1
        seal::Ciphertext unique;
        encryptor->encrypt(p_one, unique);
        // for j in range(0, 128):
        for (size_t j = 0; j < 128; ++j)
        {
            // # compute a_id[i]== b_id[j]
            // t_start = Time::now();
            // equal: sf64 = 1
            seal::Ciphertext equal;
            encryptor->encrypt(p_one, equal);
            // for k in range(0, 8):
            for (size_t k = 0; k < 8; ++k)
            {
                // # a xor b == (a-b)^2
                // x = (a_id[i][k] - b_id[j][k])**2
                seal::Ciphertext x;
                evaluator->sub(a_id[i * 8 + k], b_id[j * 8 + k], x);
                evaluator->square_inplace(x);
                evaluator->relinearize_inplace(x, *relin_keys);
                // # not x == 1 - x
                // nx = 1 - x
                encryptor->encrypt(p_one, one);
                seal::Ciphertext nx;
                evaluator->sub(one, x, nx);
                // equal = equal * nx
                evaluator->multiply_inplace(equal, nx);
                evaluator->relinearize_inplace(equal, *relin_keys);
            }
            // nequal = 1 - equal
            seal::Ciphertext nequal;
            evaluator->sub(one, equal, nequal);
            // unique = unique * nequal
            evaluator->multiply_inplace(unique, nequal);
            evaluator->relinearize_inplace(unique, *relin_keys);
        }
        seal::Ciphertext product;
        evaluator->multiply(unique, a_data[i], product);
        evaluator->relinearize_inplace(product, *relin_keys);
        evaluator->add_inplace(sum, product);
    }

    //  return sum
    Timepoint t_end = Time::now();
    log_time(ss_time, t_start, t_end, true);
    std::cout << "Time taken:  " << ss_time.str() << " ms" << std::endl;
}