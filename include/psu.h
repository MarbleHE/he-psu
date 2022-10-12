#include "seal/seal.h"
#include <set>
#include <cassert>

// TODO: Move all the definitions to the *.cpp file once it all works properly :)

namespace psu
{
    /// @brief Identifiers are 8-bit numbers
    /// Identifiers are represented bit-wise across ctxts and batched, one identifier per slot.
    typedef std::vector<seal::Ciphertext> encrypted_identifiers;

    /// @brief Encrypt a set in the necessary format for the given parameters, replicating the set as many times as possible to perform private set union with a set of size target_size
    /// @param set WARNING! While implemented as 32 bit unsigned integers, the elements must only be 8-bit numbers!
    /// @param target_size Size of the other set that we want to compute the union of
    /// @param encoder SEAL encoder to use
    /// @param encryptor SEAL encrytor to use
    /// @return A set of
    encrypted_identifiers encrypt_set_a(const std::set<uint32_t> &set, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
    {
        std::vector<std::vector<uint64_t>> values(encoder.slot_count(), std::vector<uint64_t>(8, 0));

        // Encode the repetitions, assuming both sets are the same size
        // Rotate it by one each time
        for (size_t r = 0; r < set.size(); ++r)
        {
            size_t idx = 0;
            for (auto id : set)
            {
                for (size_t b = 0; b < 8; ++b)
                {
                    values[r * set.size() + ((idx + r) % set.size())][b] = (id >>= 1) % 2;
                }
                ++idx;
            }
        }

        // // Now do one non-rotated one again so that we get the entire set (opposite site is all zeros)
        // size_t idx = 0;
        // for (auto id : set)
        // {
        //     for (size_t b = 0; b < 8; ++b)
        //     {
        //         values[set.size() * set.size() + idx][b] = ((id >>= 1) % 2);
        //     }
        //     ++idx;
        // }

        // The rest is already set to zero!

        // Now encrypt this into 8 ciphertext
        encrypted_identifiers output(8);
        for (size_t b = 0; b < 8; ++b)
        {
            seal::Plaintext ptxt;
            encoder.encode(values[b], ptxt);
            seal::Ciphertext ctxt;
            encryptor.encrypt(ptxt, ctxt);
            output[b] = ctxt;
        }
        return output;
    }

    encrypted_identifiers encrypt_set_b(const std::set<uint32_t> &set, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
    {
        std::vector<std::vector<uint64_t>> values(encoder.slot_count(), std::vector<uint64_t>(8, 0));

        // Encode many repetitions, one each for a permutation of the other set (which we assume is the same size)
        for (size_t r = 0; r < set.size(); ++r)
        {
            size_t idx = 0;
            for (auto id : set)
            {
                for (size_t b = 0; b < 8; ++b)
                {
                    values[r * set.size() + idx][b] = (id >>= 1) % 2;
                }
                ++idx;
            }
        }

        // The rest is already set to zeros!

        // Now encrypt this into 8 ciphertext
        encrypted_identifiers output(8);
        for (size_t b = 0; b < 8; ++b)
        {
            seal::Plaintext ptxt;
            encoder.encode(values[b], ptxt);
            seal::Ciphertext ctxt;
            encryptor.encrypt(ptxt, ctxt);
            output[b] = ctxt;
        }
        return output;
    }

    /// @brief
    /// This computes B \ A assuming |A|=|B|=2^k for some integer k, where the elements of A and B are 8-bit identifiers.
    /// It requires very specifically encrypted inputs (see further documentation).
    /// @param input_a must be all possible permutations of A, i.e. |A| permuted repetitions.
    /// @param input_b must be |B| repetitions of B, all in the *same* order
    /// @return A ciphertext containing 0 in slot i  iff the i-th element in B is also in A
    seal::Ciphertext compute_b_minus_a_bools(encrypted_identifiers &input_a, encrypted_identifiers &input_b, const seal::Ciphertext &data_a, const seal::Ciphertext &data_b, size_t set_size, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor, const seal::SEALContext &context, const seal::RelinKeys &rlk, const seal::GaloisKeys &glk, seal::Evaluator &evaluator)
    {

        // compute the sum over A
        seal::Ciphertext rot_a;
        seal::Ciphertext sum_a = data_a;
        for (size_t i = set_size / 2; i > 0; i /= 2)
        {
            evaluator.rotate_columns(sum_a, glk, rot_a);
            evaluator.multiply_inplace(sum_a, rot_a);
            evaluator.relinearize_inplace(sum_a, rlk);
        }

        // Sadly there's no sub_plain for the direction we need (1 - ctxt)
        // so we need to encrypt a ctxt full of ones
        std::vector<uint64_t> ones(encoder.slot_count(), 1);
        seal::Plaintext ones_ptxt;
        encoder.encode(ones, ones_ptxt);
        seal::Ciphertext ones_ctxt;
        encryptor.encrypt(ones_ptxt, ones_ctxt);

        // Overwrite a with !(a XOR b) which is 1 iff a = b
        for (size_t b = 0; b < 8; ++b)
        {
            // Compute XOR as (a-b)^2
            evaluator.sub_inplace(input_a[b], input_b[b]);
            evaluator.square_inplace(input_a[b]);
            evaluator.relinearize_inplace(input_a[b], rlk);

            // Compute NOT as 1 - x
            evaluator.sub(ones_ctxt, input_a[b], input_a[b]);
        }

        // Now we want the product of all 8 elements but in log(8) depth
        // thankfully, seal has a helper function for this!
        seal::Ciphertext output(context);
        evaluator.multiply_many(input_a, rlk, output);

        // And finally, we want to invert again
        evaluator.sub(ones_ctxt, output, output);

        // now output[i] = 0 <=> a and b were the same <=> its in both sets!

        // Now we need to collapse everything back to a single representation.
        // Since the A side is all kinds of rotated, we have to look at B instead.
        // The goal is to have the first SET_SIZE slots be 0 iff the element in set B is also present in set A

        seal::Ciphertext rot;
        for (size_t i = set_size / 2; i > 0; i /= 2)
        {
            evaluator.rotate_columns(output, glk, rot);
            evaluator.multiply_inplace(output, rot);
            evaluator.relinearize_inplace(output, rlk);
        }

        // now multiply the mask with B
        evaluator.multiply_inplace(output, data_b);
        evaluator.relinearize_inplace(output, rlk);

        // now add all the elements in B
        // compute the sum over A
        seal::Ciphertext rot_b;
        for (size_t i = set_size / 2; i > 0; i /= 2)
        {
            evaluator.rotate_columns(output, glk, rot_b);
            evaluator.multiply_inplace(output, rot_b);
            evaluator.relinearize_inplace(output, rlk);
        }

        // and finally, add with the sum of A
        evaluator.add_inplace(output, sum_a);

        return output;
    }

    /// Convert bits back to set
    std::set<uint32_t> bits_to_set(const std::set<uint32_t> &set_a, const std::set<uint32_t> &set_b, const std::vector<uint64_t> &bits)
    {
        // start with set a
        std::set<uint32_t> result = set_a;

        assert(set_a.size() == set_b.size() && "SETS MUST HAVE THE SAME SIZE");

        auto it = set_b.begin();
        for (size_t i = 0; i < set_b.size(); ++i)
        {

            if (bits[i])
            {
                result.insert(*it);
            }
            ++it;
        }
        return result;
    }

}