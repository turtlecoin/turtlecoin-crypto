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

#include "ring_signature_borromean.h"

#include "scalar_transcript.h"

/**
 * Separate hash domains are used at different points in the construction and verification
 * processes to avoid scalar collisions in different stages of the construction and verification
 * TLDR; these are hash salts
 */
static const crypto_scalar_t BORROMEAN_DOMAIN_0 = {0x42, 0x6f, 0x72, 0x72, 0x6f, 0x6d, 0x65, 0x61, 0x6e, 0x20, 0x52,
                                                   0x69, 0x6e, 0x67, 0x53, 0x69, 0x67, 0x73, 0x20, 0x62, 0x79, 0x20,
                                                   0x49, 0x42, 0x75, 0x72, 0x6e, 0x4d, 0x79, 0x43, 0x64, 0x20};

namespace Crypto::RingSignature::Borromean
{
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_borromean_signature_t &borromean_signature)
    {
        const auto ring_size = public_keys.size();

        if (!borromean_signature.check_construction(ring_size))
        {
            return false;
        }

        const auto &signature = borromean_signature.signatures;

        if (!key_image.check_subgroup())
        {
            return false;
        }

        crypto_scalar_t sum;

        crypto_scalar_transcript_t transcript(BORROMEAN_DOMAIN_0, message_digest);

        for (size_t i = 0; i < ring_size; i++)
        {
            // HP = [Hp(P)] mod l
            const auto HP = hash_to_point(public_keys[i]);

            // L = [(s[i].L * P) + (s[i].R * G)] mod l
            const auto L = signature[i].LR.L.dbl_mult(public_keys[i], signature[i].LR.R, Crypto::G);

            // R = [(s[i].R * HP) + (s[i].L * I)] mod l
            const auto R = signature[i].LR.R.dbl_mult(HP, signature[i].LR.L, key_image);

            // sum += L
            sum += signature[i].LR.L;

            transcript.update(L, R);
        }

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // ([H(prefix || L || R) - sum] mod l) != 0
        return (challenge - sum).is_nonzero();
    }

    std::tuple<bool, crypto_borromean_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        size_t real_output_index,
        const crypto_borromean_signature_t &borromean_signature,
        const std::vector<crypto_scalar_t> &partial_signing_scalars)
    {
        const auto &signature = borromean_signature.signatures;

        if (signature.empty() || real_output_index >= signature.size())
        {
            return {false, {}};
        }

        if (!signing_scalar.valid())
        {
            return {false, {}};
        }

        for (const auto &sig : signature)
        {
            if (!sig.LR.L.valid() || !sig.LR.R.valid())
            {
                return {false, {}};
            }
        }

        for (const auto &partial_signing_scalar : partial_signing_scalars)
        {
            if (!partial_signing_scalar.valid())
            {
                return {false, {}};
            }
        }

        std::vector<crypto_signature_t> finalized_signature(signature);

        const auto partial_scalar = generate_partial_signing_scalar(real_output_index, signature, signing_scalar);

        /**
         * If we have the full signing scalar (secret_ephemeral) then we can complete the signature quickly
         */
        if (partial_signing_scalars.empty())
        {
            // s[i].R = [alpha_scalar - (p * sL)] mod l
            finalized_signature[real_output_index].LR.R -= partial_scalar;
        }
        else /** Otherwise, we're using partial signing scalars (multisig) */
        {
            // create a copy of our partial signing scalars for computation and handling
            crypto_scalar_vector_t keys(partial_signing_scalars);

            // add the partial scalar to the vector
            keys.append(partial_scalar);

            /**
             * Remove any duplicate keys from the scalars that are being added together as we only use
             * unique scalars when computing the resultant scalar
             * p = [pk1 + pk2 + pk3 + ...] mod l
             */
            const auto derived_scalar = keys.dedupe_sort().sum();

            // our derived scalar should never be 0
            if (!derived_scalar.valid())
            {
                return {false, {}};
            }

            /**
             * Subtract the result of the aggregated signing scalars from the alpha_scalar value that was
             * supplied by the prepared ring signature to arrive at the final value to complete the
             * given ring signature
             */
            // s[i].R = [alpha_scalar - p]
            finalized_signature[real_output_index].LR.R -= derived_scalar;
        }

        return {true, crypto_borromean_signature_t(finalized_signature, borromean_signature.offsets)};
    }

    crypto_scalar_t generate_partial_signing_scalar(
        size_t real_output_index,
        const crypto_borromean_signature_t &borromean_signature,
        const crypto_secret_key_t &spend_secret_key)
    {
        const auto &signature = borromean_signature.signatures;

        SCALAR_OR_THROW(spend_secret_key);

        for (const auto &sig : signature)
        {
            SCALAR_OR_THROW(sig.LR.L);

            SCALAR_OR_THROW(sig.LR.R);
        }

        if (signature.empty() || real_output_index >= signature.size())
        {
            throw std::range_error("real output index must not exceed signature set size");
        }

        // asL = (s[i].L * a) mod l
        const auto partial_signing_scalar = signature[real_output_index].LR.L * spend_secret_key;

        if (!partial_signing_scalar.valid())
        {
            throw std::runtime_error("Partial signing scalar is zero");
        }

        return partial_signing_scalar;
    }

    std::tuple<bool, crypto_borromean_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_secret_key_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys)
    {
        if (!secret_ephemeral.valid())
        {
            return {false, {}};
        }

        const auto ring_size = public_keys.size();

        // find our real output in the list
        size_t real_output_index = -1;

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * G;

        for (size_t i = 0; i < ring_size; i++)
        {
            if (public_ephemeral == public_keys[i])
            {
                real_output_index = i;
            }
        }

        // if we could not find the public ephemeral in the list, fail
        if (real_output_index == -1)
        {
            return {false, {}};
        }

        // generate the key image to include in the ring signature
        const auto key_image = generate_key_image(public_ephemeral, secret_ephemeral);

        auto [prep_success, signature] =
            prepare_ring_signature(message_digest, key_image, public_keys, real_output_index);

        if (!prep_success)
        {
            return {false, {}};
        }

        return complete_ring_signature(secret_ephemeral, real_output_index, signature);
    }

    std::tuple<bool, crypto_borromean_signature_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index)
    {
        const auto ring_size = public_keys.size();

        if (real_output_index >= ring_size)
        {
            return {false, {}};
        }

        if (!key_image.check_subgroup())
        {
            return {false, {}};
        }

    try_again:
        // help to provide stronger RNG for the alpha scalar
        crypto_scalar_transcript_t alpha_transcript(message_digest, key_image, Crypto::random_scalar());

        alpha_transcript.update(public_keys);

        const auto alpha_scalar = alpha_transcript.challenge();

        /**
         * An alpha_scalar of ZERO results in a leakage of the real signing key in the resulting
         * signature construction mechanisms
         */
        if (alpha_scalar == ZERO)
        {
            return {false, {}};
        }

        std::vector<crypto_signature_t> signature(ring_size);

        crypto_scalar_t sum;

        crypto_scalar_transcript_t transcript(BORROMEAN_DOMAIN_0, message_digest);

        for (size_t i = 0; i < ring_size; i++)
        {
            crypto_point_t L, R;

            // HP = [Hp(P)] mod l
            const auto HP = Crypto::hash_to_point(public_keys[i]);

            if (i == real_output_index)
            {
                // L = (alpha_scalar * G) mod l
                L = alpha_scalar * G;

                // R = (alpha_scalar * HP) mod l
                R = alpha_scalar * HP;
            }
            else
            {
                signature[i].LR.L = random_scalar();

                signature[i].LR.R = random_scalar();

                // L = [(s[i].L * P) + (s[i].R * G)] mod l
                L = signature[i].LR.L.dbl_mult(public_keys[i], signature[i].LR.R, Crypto::G);

                // R = [(s[i].R * I) + (s[i].L * HP)] mod l
                R = signature[i].LR.R.dbl_mult(HP, signature[i].LR.L, key_image);

                // sum += s[i].L
                sum += signature[i].LR.L;
            }

            transcript.update(L, R);
        }

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            goto try_again;
        }

        // sL = ([H(prefix || L's || R's)] - sum) mod l
        signature[real_output_index].LR.L = challenge - sum;

        // this is the prepared portion of the real output signature index
        signature[real_output_index].LR.R = alpha_scalar;

        return {true, crypto_borromean_signature_t(signature)};
    }
} // namespace Crypto::RingSignature::Borromean
