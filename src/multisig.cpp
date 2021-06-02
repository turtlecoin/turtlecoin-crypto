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

#include "multisig.h"

namespace Crypto::Multisig
{
    crypto_secret_key_t generate_multisig_secret_key(
        const crypto_public_key_t &their_public_key,
        const crypto_secret_key_t &our_secret_key)
    {
        SCALAR_NZ_OR_THROW(our_secret_key);

        // Multiply the secret key by their public key point
        const auto point = (our_secret_key * their_public_key).mul8();

        // s = [H(multisig_secret_key)] mod l
        return hash_to_scalar(point);
    }

    std::vector<crypto_secret_key_t> generate_multisig_secret_keys(
        const std::vector<crypto_public_key_t> &their_public_keys,
        const crypto_secret_key_t &our_secret_key)
    {
        SCALAR_NZ_OR_THROW(our_secret_key);

        const auto keys = crypto_point_vector_t(their_public_keys).dedupe_sort();

        std::vector<crypto_secret_key_t> results(keys.size());

        for (size_t i = 0; i < keys.size(); ++i)
        {
            results[i] = generate_multisig_secret_key(keys[i], our_secret_key);
        }

        return results;
    }

    crypto_public_key_t generate_shared_public_key(const std::vector<crypto_public_key_t> &public_keys)
    {
        crypto_point_vector_t keys(public_keys);

        /**
         * Remove any duplicate keys from the keys that are being added together as we only
         * want to add together unique values of keys then add them all together
         * Z = [A + B + C + ...] mod l
         */
        return keys.dedupe_sort().sum();
    }

    crypto_secret_key_t generate_shared_secret_key(const std::vector<crypto_secret_key_t> &secret_keys)
    {
        for (const auto &key : secret_keys)
        {
            SCALAR_NZ_OR_THROW(key);
        }

        crypto_scalar_vector_t keys(secret_keys);

        /**
         * Remove any duplicate keys from the keys that are being added together as we only
         * want to add together unique values of keys then add them all together
         * z = [a + b + c + ...] mod l
         */
        return keys.dedupe_sort().sum();
    }

    size_t rounds_required(size_t participants, size_t threshold)
    {
        return participants - threshold + 1;
    }
} // namespace Crypto::Multisig
