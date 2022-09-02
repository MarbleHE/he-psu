#include "psu.h"
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <cassert>

int main()
{
    std::cout << "We will compute the set union between two sets (of the same size) encrypted under the same key:" << std::endl;
    const size_t SET_SIZE = 16;
    assert(pow(2.0, log2(SET_SIZE)) == SET_SIZE && "SET SIZE MUST BE A POWER OF TWO");

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

    std::cout << "Now the third party (C) computes the private set union and returns the result to A:" << std::endl;

    auto bits = psu::compute_psu_bools(input_a, input_b, SET_SIZE, *a.encoder, *a.encryptor, *a.context, *a.relin_keys, *a.galois_keys, *a.evaluator);

    std::cout << "Now we'll verify the result:" << std::endl;

    // Decrypt the result
    auto bits_dec = a.decrypt(bits);

    // Get the "real" sets
    auto set_a = a.get_set_for_testing();
    auto set_b = b.get_set_for_testing();

    // Convert bits to an actual union:
    auto result = psu::bits_to_set(set_a, set_b, bits_dec);

    // Compute "correct" union
    std::set<uint32_t> actual_union;
    std::set_union(set_a.begin(), set_a.end(), set_b.begin(), set_b.end(),
                   std::inserter(actual_union, actual_union.begin()));

    if (result == actual_union)
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
}