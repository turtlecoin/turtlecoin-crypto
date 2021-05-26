// Copyright (c) 2020-2021, The TurtleCoin Developers
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include "crypto_vector_types.h"
#include "hashing.h"


#ifndef CRYPTO_ENTROPY_BYTES
#define CRYPTO_ENTROPY_BYTES 16384 // 16KiB
#endif

#ifndef SEED_GENERATION_ITERATIONS
#define SEED_GENERATION_ITERATIONS 1000
#endif

namespace Crypto
{
    /**
     * Calculates the exponent of 2^e that matches the target value
     * @param target_value
     * @return
     */
    std::tuple<bool, size_t> calculate_base2_exponent(const size_t &target_value);

    /**
     * Checks to validate that the given value is a point on the curve
     * @param value
     * @return
     */
    template<typename T> bool check_point(const T &value)
    {
        return crypto_point_t::check(value);
    }

    /**
     * Checks to validate that the given value is a reduced scalar
     * @param value
     * @return
     */
    template<typename T> bool check_scalar(const T &value)
    {
        return crypto_scalar_t::check(value);
    }

    /**
     * Generates a commitment tensor point
     * @param point
     * @param i
     * @param j
     * @param k
     * @return
     */
    crypto_point_t commitment_tensor_point(const crypto_point_t &point, size_t i, size_t j, size_t k = 0);

    /**
     * Calculates a convolution of a degree-one polynomial
     * @param x
     * @param y
     * @return
     */
    std::vector<crypto_scalar_t> convolve(const crypto_scalar_vector_t &x, const std::vector<crypto_scalar_t> &y);

    /**
     * Generates the derivation scalar
     * Ds = H(D || output_index) mod l
     * @param derivation
     * @param output_index
     * @param scalar
     */
    crypto_scalar_t derivation_to_scalar(const crypto_derivation_t &derivation, uint64_t output_index = 0);

    /**
     * Calculates the public ephemeral given the derivation and the destination public key
     * P = [(Ds * G) + B] mod l
     * @param derivation
     * @param public_key
     * @param public_ephemeral
     * @return
     */
    crypto_public_key_t
        derive_public_key(const crypto_scalar_t &derivation_scalar, const crypto_public_key_t &public_key);

    /**
     * Calculates the secret ephemeral given the derivation and the destination secret key
     * p = (Ds + b) mod l
     * @param derivation
     * @param base
     * @param secret_ephemeral
     * @return
     */
    crypto_secret_key_t
        derive_secret_key(const crypto_scalar_t &derivation_scalar, const crypto_secret_key_t &secret_key);

    /**
     * Generates a key derivation
     * D = (a * B) mod l
     * @param secret_key
     * @param public_key
     * @param derivation
     * @return
     */
    crypto_derivation_t
        generate_key_derivation(const crypto_public_key_t &public_key, const crypto_secret_key_t &secret_key);

    /**
     * Generates a key image such that
     * I = Hp(P) * x
     * @param public_ephemeral
     * @param secret_ephemeral
     * @param key_image
     * @return
     */
    crypto_key_image_t
        generate_key_image(const crypto_public_key_t &public_ephemeral, const crypto_secret_key_t &secret_ephemeral);

    /**
     * Generates a key image using a set of partial key images
     * that have been provided by the participants in a multisig wallet
     * I = (Hp(P) * Ds) + pk1 + pk2 + pk3 ...
     * @param public_ephemeral
     * @param derivation_scalar
     * @param partial_key_images
     * @param key_image
     * @return
     */
    crypto_key_image_t generate_key_image(
        const crypto_public_key_t &public_ephemeral,
        const crypto_scalar_t &derivation_scalar,
        const std::vector<crypto_key_image_t> &partial_key_images);

    /**
     * Generates a key image such that
     * I = (1/x) * U
     * @param secret_ephemeral
     * @return
     */
    crypto_key_image_t generate_key_image_v2(const crypto_scalar_t &secret_ephemeral);

    /**
     * Generates a set of random keys
     * a = random_scalar()
     * A = (a * G) mod l
     *
     * NOTE: Keys generated by this method should NEVER be used for in wallet addresses.
     * Please refer to generate_wallet_spend_keys() and generate_wallet_view_keys()
     * for the deterministic methods to generate keys from a seed that allow for
     * recoverable keys.
     *
     */
    std::tuple<crypto_public_key_t, crypto_secret_key_t> generate_keys();

    /**
     * Generates a new wallet seed and uses the provided extra entropy if provided
     *
     * @param extra_entropy
     * @return
     */
    std::tuple<crypto_seed_t, std::vector<std::string>, uint64_t>
        generate_wallet_seed(const std::vector<uint8_t> &extra_entropy = {});

    /**
     * Generates deterministic subwallet keys from the wallet seed value.
     *
     * For compatibility & security purposes, all wallet keys and addresses, should be derived from
     * the wallet seed and the seed should never be used directly.
     *
     * Subwallets are generated by injecting deterministic salt into the hashing process
     * whereby it is nearly impossible to reconstruct the spend keys without knowing the
     * subwallet index and the seed value that they were derived from.
     *
     * @param wallet_seed
     * @param subwallet_index
     * @return
     */
    std::tuple<crypto_public_key_t, crypto_secret_key_t>
        generate_wallet_spend_keys(const crypto_seed_t &wallet_seed, uint64_t subwallet_index = 0);

    /**
     * Calculates deterministic wallet view keys from the given wallet seed value.
     *
     * For compatibility & security purposes, all wallet keys and addresses, should be derived from
     * the wallet seed and the seed should never be used directly.
     *
     * @param spend_secret_key
     * @return
     */
    std::tuple<crypto_public_key_t, crypto_secret_key_t> generate_wallet_view_keys(const crypto_seed_t &wallet_seed);

    /**
     * Hashes the given data and turns it directly into a point
     * @param data
     * @param length
     * @return
     */
    crypto_point_t hash_to_point(const void *data, size_t length);

    /**
     * Hashes the given pod structures and turns it directly into a point
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> crypto_point_t hash_to_point(const T &input)
    {
        return hash_to_point(input.data(), input.size());
    }

    /**
     * Hashes the given data and returns the resulting scalar for said hash
     * s = H(data) mod l
     * @param data
     * @param length
     * @return
     */
    crypto_scalar_t hash_to_scalar(const void *data, size_t length);

    /**
     * Hashes the given input and returns the resulting scalar for said hash
     * This is generally only used during key image operations
     * s = H(data) mod l
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> crypto_scalar_t hash_to_scalar(const T &input)
    {
        return hash_to_scalar(input.data(), input.size());
    }

    /**
     * Compute the Kronecker delta
     * @param a
     * @param b
     * @return
     */
    crypto_scalar_t kronecker_delta(const crypto_scalar_t &a, const crypto_scalar_t &b);

    /**
     * Rounds the given value to the next power of 2
     * @param value
     * @return
     */
    size_t pow2_round(size_t value);

    /**
     * Generate a random hash
     * @return
     */
    crypto_hash_t random_hash();

    /**
     * Generate a vector of random hashes
     * @param count
     * @return
     */
    std::vector<crypto_hash_t> random_hashes(size_t count = 1);

    /**
     * Generate a random point
     * @return
     */
    crypto_point_t random_point();

    /**
     * Generate a vector of random points
     * @param count
     * @return
     */
    std::vector<crypto_point_t> random_points(size_t count = 1);

    /**
     * Generates a random scalar
     * @return
     */
    crypto_scalar_t random_scalar();

    /**
     * Generate an vector of random scalars
     * @param count
     * @return
     */
    std::vector<crypto_scalar_t> random_scalars(size_t count = 1);

    /**
     * Calculates the public key for the given secret key
     * A = (a * G) mod l
     * @param secret_key
     * @param public_key
     * @return
     */
    crypto_public_key_t secret_key_to_public_key(const crypto_secret_key_t &secret_key);

    /**
     * Much like derive_public_key() but determines the public_key used from the public ephemeral
     * B = P - [H(D || output_index) mod l]
     * @param derivation
     * @param output_index
     * @param derived_key
     * @param public_ephemeral
     * @return
     */
    crypto_public_key_t underive_public_key(
        const crypto_derivation_t &derivation,
        uint8_t output_index,
        const crypto_public_key_t &public_ephemeral);
} // namespace Crypto

#endif // CRYPTO_COMMON_H
