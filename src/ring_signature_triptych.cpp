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
//
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

#include "ring_signature_triptych.h"

#include "gray_code_generator.h"
#include "scalar_transcript.h"

static const crypto_scalar_t TRIPTYCH_DOMAIN_0 = {0x20, 0x20, 0x20, 0x54, 0x52, 0x54, 0x4c, 0x20, 0x54, 0x72, 0x69,
                                                  0x70, 0x74, 0x79, 0x63, 0x68, 0x20, 0x62, 0x79, 0x20, 0x49, 0x42,
                                                  0x75, 0x72, 0x6e, 0x4d, 0x79, 0x43, 0x44, 0x20, 0x20, 0x20};

static const auto TRIPTYCH_DOMAIN_1 = Crypto::hash_to_point(TRIPTYCH_DOMAIN_0);

static const auto TRIPTYCH_DOMAIN_2 = Crypto::hash_to_scalar(TRIPTYCH_DOMAIN_1);

typedef std::vector<std::vector<crypto_scalar_t>> triptych_scalar_vector_t;

static inline crypto_point_t commitment_tensor(const triptych_scalar_vector_t &v, const crypto_scalar_t &r)
{
    auto C = Crypto::Z;

    for (size_t i = 0; i < v.size(); ++i)
    {
        for (size_t j = 0; j < v[i].size(); ++j)
        {
            C += v[i][j] * Crypto::commitment_tensor_point(TRIPTYCH_DOMAIN_1, i, j);
        }
    }

    C += r * Crypto::H;

    return C;
}

static inline triptych_scalar_vector_t init_triptych_scalar_vector(
    size_t d1,
    size_t d2,
    bool random = false,
    const crypto_scalar_t &initial_value = Crypto::ZERO)
{
    triptych_scalar_vector_t result(d1);

    for (auto &level1 : result)
    {
        if (random)
        {
            level1 = Crypto::random_scalars(d2);
        }
        else
        {
            level1 = std::vector<crypto_scalar_t>(d2, initial_value);
        }
    }

    return result;
}

namespace Crypto::RingSignature::Triptych
{
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_triptych_signature_t &signature,
        const std::vector<crypto_pedersen_commitment_t> &commitments)
    {
        const size_t n = 2;

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found || m < 2)
        {
            return false;
        }

        if (public_keys.size() != commitments.size())
        {
            return false;
        }

        if (!key_image.check_subgroup())
        {
            return false;
        }

        if (!signature.check_construction(m, n))
        {
            return false;
        }

        auto tr = crypto_scalar_transcript_t(TRIPTYCH_DOMAIN_2, message_digest);

        tr.update(public_keys);

        tr.update(commitments);

        tr.update(signature.pseudo_commitment);

        tr.update(key_image);

        tr.update(signature.commitment_image);

        tr.update(signature.A);

        tr.update(signature.B);

        tr.update(signature.C);

        tr.update(signature.D);

        const auto mu = tr.challenge();

        if (!mu.valid())
        {
            return false;
        }

        tr.update(signature.X);

        tr.update(signature.Y);

        const auto x = tr.challenge();

        if (!x.valid())
        {
            return false;
        }

        auto f = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            f[j][0] = x;

            for (size_t i = 1; i < n; ++i)
            {
                f[j][i] = signature.f[j][i - 1];

                f[j][0] -= f[j][i];
            }
        }

        // A/B Check
        for (size_t j = 0; j < m; ++j)
        {
            f[j][0] = x;

            for (size_t i = 1; i < n; ++i)
            {
                f[j][0] -= f[j][i];
            }
        }

        if (commitment_tensor(f, signature.zA) != (x * signature.B) + signature.A)
        {
            return false;
        }

        auto fx = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                fx[j][i] = f[j][i] * (x - f[j][i]);
            }
        }

        if (commitment_tensor(fx, signature.zC) != (x * signature.C) + signature.D)
        {
            return false;
        }

        auto RX = Crypto::Z, RY = Crypto::Z;

        auto t = Crypto::ONE;

        for (size_t j = 0; j < m; ++j)
        {
            t *= f[j][0];
        }

        GrayCodeGenerator gray_codes(n, m);

        for (size_t k = 0; k < gray_codes.size(); ++k)
        {
            const auto &gray_update = gray_codes[k];

            if (k > 0)
            {
                t *= f[gray_update[0]][gray_update[1]].invert() * f[gray_update[0]][gray_update[2]];
            }

            RX += t * (public_keys[k] + (mu * (Crypto::EIGHT * (commitments[k] - signature.pseudo_commitment))));

            RY += t * (Crypto::U + (mu * signature.commitment_image));
        }

        for (size_t j = 0; j < m; ++j)
        {
            const auto xpow = x.pow(j);

            RX -= xpow * signature.X[j];

            RY -= xpow * signature.Y[j];
        }

        RX -= signature.z * Crypto::G;

        RY -= signature.z * key_image;

        return RX.empty() && RY.empty();
    }

    std::tuple<bool, crypto_triptych_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        const crypto_triptych_signature_t &signature,
        const crypto_scalar_t &xpow,
        const std::vector<crypto_scalar_t> &partial_signing_scalars)
    {
        if (!signing_scalar.valid() || !xpow.valid())
        {
            return {false, {}};
        }

        for (const auto &scalar : partial_signing_scalars)
        {
            if (!scalar.valid())
            {
                return {false, {}};
            }
        }

        auto finalized_signature = signature;

        const auto partial_scalar = generate_partial_signing_scalar(signing_scalar, xpow);

        /**
         * If we have the full signing scalar (secret_ephemeral) then we can complete the signature quickly
         */
        if (partial_signing_scalars.empty())
        {
            finalized_signature.z += partial_scalar;
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

            finalized_signature.z += derived_scalar;
        }

        return {true, finalized_signature};
    }

    crypto_scalar_t
        generate_partial_signing_scalar(const crypto_scalar_t &spend_secret_key, const crypto_scalar_t &xpow)
    {
        SCALAR_NZ_OR_THROW(spend_secret_key);

        SCALAR_NZ_OR_THROW(xpow);

        const auto partial_signing_scalar = spend_secret_key * xpow;

        SCALAR_NZ_OR_THROW(partial_signing_scalar);

        return partial_signing_scalar;
    }

    std::tuple<bool, crypto_triptych_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_secret_key_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found || m < 2)
        {
            return {false, {}};
        }

        if (public_keys.size() != input_commitments.size())
        {
            return {false, {}};
        }

        const auto ring_size = public_keys.size();

        if (!secret_ephemeral.valid() || !input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}};
        }

        // find our real input in the list;
        size_t real_output_index = -1;

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

        for (size_t i = 0; i < ring_size; i++)
        {
            const auto derived_commitment = Crypto::EIGHT * (input_commitments[i] - pseudo_commitment);

            if (public_ephemeral == public_keys[i] && public_commitment == derived_commitment)
            {
                real_output_index = i;
            }
        }

        /**
         * if we could not find the related public key(s) in the list or the proper
         * commitments provided, then fail as we cannot generate a valid signature
         */
        if (real_output_index == -1)
        {
            return {false, {}};
        }

        const auto key_image = Crypto::generate_key_image_v2(secret_ephemeral);

        const auto [gen_success, signature, x_pow] = prepare_ring_signature(
            message_digest,
            key_image,
            public_keys,
            real_output_index,
            input_blinding_factor,
            input_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);

        if (!gen_success)
        {
            return {false, {}};
        }

        return complete_ring_signature(secret_ephemeral, signature, x_pow);
    }

    std::tuple<bool, crypto_triptych_signature_t, crypto_scalar_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        const size_t n = 2;

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found || m < 2)
        {
            return {false, {}, {}};
        }

        if (public_keys.size() != input_commitments.size())
        {
            return {false, {}, {}};
        }

        if (!key_image.check_subgroup())
        {
            return {false, {}, {}};
        }

        if (!input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}, {}};
        }

        // See below for more detail
        const auto blinding_factor = input_blinding_factor - pseudo_blinding_factor;

        /**
         * TLDR: If we know the difference between the input blinding scalar and the
         * pseudo output blinding scalar then we can use that difference as the secret
         * key for the difference between the input commitment and the pseudo commitment
         * thus providing no amount component differences in the commitments between the
         * two and hence we are committing (in a non-revealing way) that the pseudo output
         * commitment is equivalent to ONE of the input commitments in the set
         */
        const auto commitment = Crypto::EIGHT * (input_commitments[real_output_index] - pseudo_commitment);

        const auto public_commitment = blinding_factor * Crypto::G;

        /**
         * Quick sanity check to make sure that the computed blinding factor delta has a
         * resulting public point that is the same as the commitment that we can sign for above
         */
        if (commitment != public_commitment)
        {
            return {false, {}, {}};
        }

        auto N = public_keys.size();

        const crypto_key_image_t commitment_image = (input_blinding_factor - pseudo_blinding_factor) * key_image;

    try_again:
        const auto rA = Crypto::random_scalar(), rB = Crypto::random_scalar(), rC = Crypto::random_scalar(),
                   rD = Crypto::random_scalar();

        if (!rA.valid() || !rB.valid() || !rC.valid() || !rD.valid())
        {
            goto try_again;
        }

        auto a = init_triptych_scalar_vector(m, n, true);

        for (size_t j = 0; j < m; ++j)
        {
            a[j][0] = Crypto::ZERO;

            for (size_t i = 1; i < n; ++i)
            {
                a[j][0] -= a[j][i];
            }
        }

        const auto A = commitment_tensor(a, rA);

        const auto gray = GrayCodeGenerator(n, m, real_output_index);

        const auto decomp_l = gray.v_value();

        auto sigma = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                sigma[j][i] = Crypto::kronecker_delta(decomp_l[j], i);
            }
        }

        const auto B = commitment_tensor(sigma, rB);

        auto a_sigma = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                a_sigma[j][i] = a[j][i] * (Crypto::ONE - Crypto::TWO * sigma[j][i]);
            }
        }

        const auto C = commitment_tensor(a_sigma, rC);

        auto a_sq = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                a_sq[j][i] = a[j][i].squared().negate();
            }
        }

        const auto D = commitment_tensor(a_sq, rD);

        auto p = init_triptych_scalar_vector(N, 0);

        auto decomp_k = std::vector<int>(m, 0);

        GrayCodeGenerator gray_codes(n, m);

        for (size_t k = 0; k < gray_codes.size(); ++k)
        {
            const auto &gray_update = gray_codes[k];

            decomp_k[gray_update[0]] = gray_update[2];

            p[k] = {a[0][decomp_k[0]], Crypto::kronecker_delta(decomp_l[0], decomp_k[0])};

            for (size_t j = 1; j < m; ++j)
            {
                p[k] = Crypto::convolve(p[k], {a[j][decomp_k[j]], Crypto::kronecker_delta(decomp_l[j], decomp_k[j])});
            }
        }

        std::vector<crypto_point_t> X(m, Crypto::Z), Y(m, Crypto::Z);

        auto tr = crypto_scalar_transcript_t(TRIPTYCH_DOMAIN_2, message_digest);

        tr.update(public_keys);

        tr.update(input_commitments);

        tr.update(pseudo_commitment);

        tr.update(key_image);

        tr.update(commitment_image);

        tr.update(A);

        tr.update(B);

        tr.update(C);

        tr.update(D);

        const auto mu = tr.challenge();

        if (!mu.valid())
        {
            goto try_again;
        }

        const auto rho = Crypto::random_scalars(m);

        for (const auto &r : rho)
        {
            if (!r.valid())
            {
                goto try_again;
            }
        }

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < N; ++i)
            {
                X[j] +=
                    p[i][j] * (public_keys[i] + (mu * (Crypto::EIGHT * (input_commitments[i] - pseudo_commitment))));

                Y[j] += p[i][j] * Crypto::U;
            }

            X[j] += rho[j] * Crypto::G;

            Y[j] += rho[j] * key_image;
        }

        tr.update(X);

        tr.update(Y);

        const auto x = tr.challenge();

        if (!x.valid())
        {
            goto try_again;
        }

        auto f = init_triptych_scalar_vector(m, n - 1);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 1; i < n; ++i)
            {
                f[j][i - 1] = (sigma[j][i] * x) + a[j][i];
            }
        }

        const auto zA = rB * x + rA;

        const auto zC = rC * x + rD;

        const auto xpow = x.pow(m);

        auto z = (mu * (input_blinding_factor - pseudo_blinding_factor)) * xpow;

        for (size_t j = 0; j < m; ++j)
        {
            z -= rho[j] * x.pow(j);
        }

        const auto signature =
            crypto_triptych_signature_t(commitment_image, pseudo_commitment, A, B, C, D, X, Y, f, zA, zC, z);

        return {true, signature, xpow};
    }
} // namespace Crypto::RingSignature::Triptych
