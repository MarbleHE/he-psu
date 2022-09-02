#include "seal/seal.h"
#include <set>

// TODO: Move all the definitions to the *.cpp file once it all works properly :)

namespace psu
{
    /// @brief Identifiers are 24-bit numbers
    /// Identifiers are represented bit-wise across ctxts and batched, one identifier per slot.
    typedef std::vector<seal::Ciphertext> encrypted_identifiers;

    /// @brief Computes (batched) bit-wise equality by computing the product of the XOR of the bits of each identifier.
    /// @param a Potentially batched encrypted identifiers
    /// @param b Potentially batched encrypted identifiers
    /// @return A ciphertext containing 1 in slot i  iff identifier a[i] and b[i] are equal
    seal::Ciphertext equal(const encrypted_identifiers &a, const encrypted_identifiers &b);

    /// @brief Encrypt a set in the necessary format for the given parameters, replicating the set as many times as possible to perform private set union with a set of size target_size
    /// @param set WARNING! While implemented as 32 bit unsigned integers, the elements must only be 24-bit numbers!
    /// @param target_size Size of the other set that we want to compute the union of
    /// @param encoder SEAL encoder to use
    /// @param encryptor SEAL encrytor to use
    /// @return A set of
    encrypted_identifiers encrypt_set_a(const std::set<uint32_t> &set, size_t target_size, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
    {
        std::vector<std::vector<uint64_t>> values(encoder.slot_count(), std::vector<uint64_t>(24));

        // Encode as many repetitions of the set as possible,
        // but shift it by 1 each time round!
        size_t repeats = encoder.slot_count() / set.size();
        for (size_t r = 0; r < repeats; ++r)
        {
            size_t idx = 0 + r;
            for (auto id : set)
            {
                for (size_t b = 0; b < 24; ++b)
                {
                    values[r * set.size() + (idx % set.size())][b] = id >> 1;
                }
                ++idx;
            }
        }

        // Now fill the rest with zeros (//TODO: This assumes 0 isn't a valid id!!)
        for (size_t idx = repeats * set.size(); idx < encoder.slot_count(); ++idx)
        {
            for (size_t b = 0; b < 24; ++b)
            {
                values[idx][b] = 0;
            }
        }

        // Now encrypt this into 24 ciphertext
        encrypted_identifiers output(24);
        for (size_t b = 0; b < 24; ++b)
        {
            seal::Plaintext ptxt;
            encoder.encode(values[b], ptxt);
            seal::Ciphertext ctxt;
            encryptor.encrypt(ptxt, ctxt);
            output[b] = ctxt;
        }
        return output;
    }

    encrypted_identifiers encrypt_set_b(const std::set<uint32_t> &set, size_t target_size, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
    {
        std::vector<std::vector<uint64_t>> values(encoder.slot_count(), std::vector<uint64_t>(24));

        // Encode as many repetitions of the set as possible
        size_t repeats = encoder.slot_count() / set.size();
        for (size_t r = 0; r < repeats; ++r)
        {
            size_t idx = 0;
            for (auto id : set)
            {
                for (size_t b = 0; b < 24; ++b)
                {
                    values[r * set.size() + idx][b] = id >> 1;
                }
                ++idx;
            }
        }

        // Now fill the rest with zeros (//TODO: This assumes 0 isn't a valid id!!)
        for (size_t idx = repeats * set.size(); idx < encoder.slot_count(); ++idx)
        {
            for (size_t b = 0; b < 24; ++b)
            {
                values[idx][b] = 0;
            }
        }

        // Now encrypt this into 24 ciphertext
        encrypted_identifiers output(24);
        for (size_t b = 0; b < 24; ++b)
        {
            seal::Plaintext ptxt;
            encoder.encode(values[b], ptxt);
            seal::Ciphertext ctxt;
            encryptor.encrypt(ptxt, ctxt);
            output[b] = ctxt;
        }
        return output;
    }

    /// @brief Decrypts a set back to a list of identifiers
    /// @param set set to decrypt
    /// @param decryptor SEAL decryptor to use
    /// @param encoder SEAL encoder, which is also a "de"coder
    /// @return
    std::set<uint32_t> decrypt_set(encrypted_identifiers &enc, const seal::Decryptor &decryptor, const seal::BatchEncoder &encoder)
    {
        std::set<uint32_t> set;
        // TODO: Implement
        return set;
    }

    seal::Ciphertext compute_psu_bools(encrypted_identifiers &input_a, size_t size_a, encrypted_identifiers &input_b, size_t size_b, const seal::SEALContext &context, const seal::RelinKeys &rlk)
    {
        // TODO: Implement
        return seal::Ciphertext(context);
    }
}