#include "seal/seal.h"
#include <set>

// TODO: Move all the definitions to the *.cpp file once it all works properly :)

namespace psu
{
    /// @brief Identifiers are 24-bit numbers
    /// Identifiers are represented bit-wise across ctxts and batched, one identifier per slot.
    typedef std::vector<seal::Ciphertext> encrypted_identifiers;

    /// @brief Encrypt a set in the necessary format for the given parameters, replicating the set as many times as possible to perform private set union with a set of size target_size
    /// @param set WARNING! While implemented as 32 bit unsigned integers, the elements must only be 24-bit numbers!
    /// @param target_size Size of the other set that we want to compute the union of
    /// @param encoder SEAL encoder to use
    /// @param encryptor SEAL encrytor to use
    /// @return A set of
    encrypted_identifiers encrypt_set_a(const std::set<uint32_t> &set, size_t target_size, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
    {
        std::vector<std::vector<uint64_t>> values(encoder.slot_count(), std::vector<uint64_t>(24, 0));

        // Encode as many repetitions of the set as possible (minus one)
        // but shift it by 1 each time round!
        size_t repeats = encoder.slot_count() / set.size();
        for (size_t r = 0; r < repeats - 1; ++r)
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

        // Now do one non-rotated one again so that we get the entire set (opposite site is all zeros)
        size_t idx = repeats - 1;
        for (auto id : set)
        {
            for (size_t b = 0; b < 24; ++b)
            {
                values[(repeats - 1) * set.size() + (idx % set.size())][b] = ((id >>= 1) % 2);
            }
            ++idx;
        }

        // Now fill the rest with zeros (This assumes 0 isn't a valid id!!)
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
        std::vector<std::vector<uint64_t>> values(encoder.slot_count(), std::vector<uint64_t>(24, 0));

        // Encode as many repetitions of the set as possible, except for the last one!
        size_t repeats = encoder.slot_count() / set.size();
        for (size_t r = 0; r < repeats - 1; ++r)
        {
            size_t idx = 0;
            for (auto id : set)
            {
                for (size_t b = 0; b < 24; ++b)
                {
                    values[r * set.size() + idx][b] = (id >>= 1) % 2;
                }
                ++idx;
            }
        }

        // Now fill the rest with zeros (This assumes 0 isn't a valid id!!)
        for (size_t idx = (repeats - 1) * set.size(); idx < encoder.slot_count(); ++idx)
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

    /// @brief Computes (batched) bit-wise equality by computing the product of the XOR of the bits of each identifier.
    /// Because of the batching scheme used, this effectively computes a vector that gives you whether or not an element is in the union
    /// @param input_a batched encrypted identifiers
    /// @param input_b batched encrypted identifiers
    /// @return A ciphertext containing 1 in slot i  iff identifier a[i] and b[i] are equal
    seal::Ciphertext compute_psu_bools(encrypted_identifiers &input_a, encrypted_identifiers &input_b, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor, const seal::SEALContext &context, const seal::RelinKeys &rlk, const seal::Evaluator &evaluator)
    {
        // Sadly there's no sub_plain for the direction we need (1 - ctxt)
        // so we need to encrypt a ctxt full of ones
        std::vector<uint64_t> ones(encoder.slot_count(), 1);
        seal::Plaintext ones_ptxt;
        encoder.encode(ones, ones_ptxt);
        seal::Ciphertext ones_ctxt;
        encryptor.encrypt(ones_ptxt, ones_ctxt);

        // Overwrite a with !(a XOR b)
        for (size_t b = 0; b < 24; ++b)
        {
            // Compute XOR as (a-b)^2
            evaluator.sub_inplace(input_a[b], input_b[b]);
            evaluator.square_inplace(input_a[b]);
            evaluator.relinearize_inplace(input_a[b], rlk);

            // Compute NOT as 1 - x
            evaluator.sub(ones_ctxt, input_a[b], input_a[b]);
        }

        // Now we want the product of all 24 elements but in log(24) depth
        // thankfully, seal has a helper function for this!
        seal::Ciphertext output(context);
        evaluator.multiply_many(input_a, rlk, output);

        // And finally, we want to invert again
        evaluator.sub(ones_ctxt, output, output);

        return output;
    }
    // Convert bits to an actual union:
    std::set<uint32_t> bits_to_set(const std::set<uint32_t> &set_a, const std::set<uint32_t> &set_b, const std::vector<uint64_t> &bits)
    {
        // start with set a
        std::set<uint32_t> result = set_a;

        size_t repeats = bits.size() / set_b.size();
        for (size_t r = 0; r < repeats - 1; ++r)
        {
            auto it = set_b.begin();
            for (size_t idx = 0; idx < set_b.size(); ++idx)
            {
                if (bits[idx])
                {
                    result.insert(*it);
                }
                if (++it == set_b.end())
                {
                    it = set_b.begin();
                }
                else
                {
                    ++it;
                }
            }
        }
    }
}