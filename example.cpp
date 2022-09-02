#include "psu.h"
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <cassert>

int main()
{
    std::cout << "We will compute the set union between two sets encrypted under the same key:" << std::endl;
    const size_t SIZE_A = 100;
    const size_t SIZE_B = SIZE_A;

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

        // Initialization
        A()
        {
            // Generate the secret set of 24 bit numbers
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(0, 1 << 23);
            for (size_t i = 0; i < SIZE_A; ++i)
            {
                set.insert(distrib(gen));
            }

            // Parameter selection
            parms = std::make_shared<seal::EncryptionParameters>(seal::scheme_type::bfv);
            size_t poly_modulus_degree = 1 << 13; // 2^14
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
        };

        psu::encrypted_identifiers encrypt_set(size_t target_size)
        {
            return psu::encrypt_set_a(set, target_size, *encoder, *encryptor);
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
    auto input_a = a.encrypt_set(SIZE_B);

    std::cout << "The second party only provides an encrypted input. This is sent to the third-party compute server." << std::endl;

    class B
    {

    public:
        // Initialization
        B()
        {
            // Generate the secret set of 24 bit numbers
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(0, 1 << 23);
            for (size_t i = 0; i < SIZE_B; ++i)
            {
                set.insert(distrib(gen));
            }
        }

        psu::encrypted_identifiers encrypt_set(size_t target_size, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
        {
            return psu::encrypt_set_b(set, target_size, encoder, encryptor);
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
    auto input_b = b.encrypt_set(SIZE_B, *a.encoder, *a.encryptor);

    std::cout << "Now the third party computes the private set union and returns the result to a:" << std::endl;

    auto bits = psu::compute_psu_bools(input_a, input_b, *a.encoder, *a.encryptor, *a.context, *a.relin_keys, *a.evaluator);

    std::cout << "Now we'll verify the result:" << std::endl;

    // Decrypt the result
    auto bits_dec = a.decrypt(bits);

    // Get the "real" sets
    auto set_a = a.get_set_for_testing();
    auto set_b = b.get_set_for_testing();

    // Convert bits to an actual union:
    std::set<uint32_t> result;
    auto it = set_a.begin();
    assert(set_a.begin() != set_a.end() && "Set a must not be empty!");
    for (size_t i = 0; i < bits_dec.size(); ++i)
    {
        if (++it == set_a.end())
        {
            it = set_a.begin();
        }
        result.insert(*it);
    }

    // Compute "correct" union
    std::set<uint32_t> actual_union;
    std::set_union(set_a.begin(), set_a.end(), set_b.begin(), set_b.end(),
                   std::inserter(actual_union, actual_union.begin()));

    if (false) // TODO: Figure how to check it
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
        for (auto &x : set_a)
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
}