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

#include "signature.h"

#include "scalar_transcript.h"

static const crypto_scalar_t SIGNATURE_DOMAIN_0 = {0x20, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x53, 0x69, 0x67,
                                                   0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x20, 0x62, 0x79, 0x20,
                                                   0x49, 0x42, 0x75, 0x72, 0x6e, 0x4d, 0x79, 0x43, 0x64, 0x20};

namespace Crypto::Signature
{
    bool check_signature(
        const crypto_hash_t &message_digest,
        const crypto_public_key_t &public_key,
        const crypto_signature_t &signature)
    {
        if (!signature.LR.L.valid() || !signature.LR.R.valid())
        {
            return false;
        }

        // P = [(l * P) + (r * G)] mod l
        const auto point = (signature.LR.L * public_key) + (signature.LR.R * G);

        crypto_scalar_transcript_t transcript(SIGNATURE_DOMAIN_0, message_digest, public_key, point);

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // [(c - sL) mod l] != 0
        return (challenge - signature.LR.L).is_nonzero();
    }

    crypto_signature_t complete_signature(
        const crypto_scalar_t &signing_scalar,
        const crypto_signature_t &signature,
        const std::vector<crypto_scalar_t> &partial_signing_scalars)
    {
        SCALAR_OR_THROW(signing_scalar);

        SCALAR_OR_THROW(signature.LR.L);

        SCALAR_OR_THROW(signature.LR.R);

        for (const auto &partial_signing_scalar : partial_signing_scalars)
        {
            SCALAR_OR_THROW(partial_signing_scalar);
        }

        auto finalized_signature = signature;

        if (partial_signing_scalars.empty() && signing_scalar != Crypto::ZERO)
        {
            finalized_signature.LR.R -= (signature.LR.L * signing_scalar);
        }
        else if (!partial_signing_scalars.empty())
        {
            // create a copy of our partial signing scalars for computation and handling
            crypto_scalar_vector_t keys(partial_signing_scalars);

            /**
             * Remove any duplicate keys from the scalars that are being added together as we only use
             * unique scalars when computing the resultant scalar
             * p = [pk1 + pk2 + pk3 + ...] mod l
             */
            const auto derived_scalar = keys.dedupe_sort().sum();

            // our derived scalar should never be 0
            if (!derived_scalar.valid())
            {
                throw std::invalid_argument("derived scalar cannot be 0");
            }

            /**
             * Subtract the result of the aggregated signing scalars from the alpha_scalar value that was
             * supplied by the prepared ring signature to arrive at the final value to complete the
             * given ring signature
             */
            // s[i].R = [alpha_scalar - p]
            finalized_signature.LR.R -= derived_scalar;
        }
        else
        {
            throw std::invalid_argument("must supply a signing scalar or partial signing keys");
        }

        return finalized_signature;
    }

    crypto_scalar_t generate_partial_signing_scalar(
        const crypto_signature_t &signature,
        const crypto_secret_key_t &spend_secret_key)
    {
        SCALAR_OR_THROW(spend_secret_key);

        SCALAR_OR_THROW(signature.LR.L);

        SCALAR_OR_THROW(signature.LR.R);

        // asL = (s.L * a) mod l
        const auto partial_signing_scalar = signature.LR.L * spend_secret_key;

        if (!partial_signing_scalar.valid())
        {
            throw std::runtime_error("Partial signing scalar is zero");
        }

        return partial_signing_scalar;
    }

    crypto_signature_t generate_signature(const crypto_hash_t &message_digest, const crypto_secret_key_t &secret_key)
    {
        SCALAR_OR_THROW(secret_key);

        // A = (a * G) mod l
        const auto public_key = secret_key * G;

        const auto signature = prepare_signature(message_digest, public_key);

        return complete_signature(secret_key, signature);
    }

    crypto_signature_t prepare_signature(const crypto_hash_t &message_digest, const crypto_public_key_t &public_key)
    {
    try_again:
        // help to provide stronger RNG for the alpha scalar
        crypto_scalar_transcript_t alpha_transcript(message_digest, public_key, Crypto::random_scalar());

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        // P = (a * G) mod l
        const auto point = alpha_scalar * G;

        crypto_scalar_transcript_t transcript(SIGNATURE_DOMAIN_0, message_digest, public_key, point);

        crypto_signature_t signature;

        signature.LR.L = transcript.challenge();

        if (!signature.LR.L.valid())
        {
            goto try_again;
        }

        signature.LR.R = alpha_scalar;

        return signature;
    }
} // namespace Crypto::Signature
