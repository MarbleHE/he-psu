#include "seal/seal.h"
#include <set>

// TODO: Move all the definitions to the *.cpp file once it all works properly :)

namespace psu
{
    /// @brief Identifiers are 24-bit numbers
    /// Identifiers are represented bit-wise across ctxts and batched, one identifier per slot.
    typedef std::array<seal::Ciphertext, 24> encrypted_identifiers;

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
    std::vector<encrypted_identifiers> encrypt_set(const std::set<uint32_t> &set, size_t target_size, const seal::BatchEncoder &encoder, const seal::Encryptor &encryptor)
    {
        std::vector<encrypted_identifiers> output;
        // TODO: Implement
        return output;
    }

    /// @brief Decrypts a set back to a list of identifiers
    /// @param set set to decrypt
    /// @param decryptor SEAL decryptor to use
    /// @param encoder SEAL encoder, which is also a "de"coder
    /// @return
    std::set<uint32_t> decrypt_set(std::vector<encrypted_identifiers> &enc, const seal::Decryptor &decryptor, const seal::BatchEncoder &encoder)
    {
        std::set<uint32_t> set;
        // TODO: Implement
        return set;
    }

    std::vector<encrypted_identifiers> compute_psu(std::vector<encrypted_identifiers> &input_a, size_t size_a, std::vector<encrypted_identifiers> &input_b, size_t size_b, const seal::SEALContext &context, const seal::RelinKeys &rlk)
    {
        // TODO: Implement
        return input_a;
    }
}