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
// https://github.com/SarangNoether/skunkworks/tree/arcturus

#include "ring_signature_arcturus.h"

/**
 * Separate hash domains are used at different points in the construction and verification
 * processes to avoid scalar collisions in different stages of the construction and verification
 * TLDR; these are hash salts
 */
static const crypto_scalar_t ARCTURUS_DOMAIN_0 = {0x20, 0x20, 0x41, 0x72, 0x63, 0x74, 0x75, 0x72, 0x75, 0x73, 0x20,
                                                  0x50, 0x72, 0x6f, 0x6f, 0x66, 0x73, 0x20, 0x62, 0x79, 0x20, 0x49,
                                                  0x42, 0x75, 0x72, 0x6e, 0x4d, 0x79, 0x43, 0x64, 0x20, 0x20};

static const auto ARCTURUS_DOMAIN_1 = Crypto::hash_to_point(ARCTURUS_DOMAIN_0);

static const auto ARCTURUS_DOMAIN_2 = Crypto::hash_to_scalar(ARCTURUS_DOMAIN_1);

typedef std::vector<std::vector<std::vector<crypto_scalar_t>>> arcturus_scalar_vector_t;

static inline crypto_scalar_t delta(const crypto_scalar_t &x, const crypto_scalar_t &y)
{
    if (x == y)
    {
        return Crypto::ONE;
    }

    return Crypto::ZERO;
}

static inline crypto_point_t com_tensor_point(size_t i, size_t j, size_t k)
{
    struct
    {
        crypto_point_t Gi;
        uint64_t i = 0, j = 0, k = 0;
    } buffer;

    buffer.Gi = ARCTURUS_DOMAIN_1;

    buffer.i = i;

    buffer.j = j;

    buffer.k = k;

    return Crypto::hash_to_point(&buffer, sizeof(buffer));
}

static inline crypto_point_t com_tensor(const arcturus_scalar_vector_t &v, const crypto_scalar_t &r)
{
    auto C = Crypto::Z;

    for (size_t i = 0; i < v.size(); ++i)
    {
        for (size_t j = 0; j < v[0].size(); ++j)
        {
            for (size_t k = 0; k < v[0][0].size(); ++k)
            {
                C += v[i][j][k] * com_tensor_point(i, j, k);
            }
        }
    }

    C += r * Crypto::H;

    return C;
}

static inline std::vector<crypto_scalar_t>
    convolve(const crypto_scalar_vector_t &x, const std::vector<crypto_scalar_t> &y)
{
    if (y.size() != 2)
    {
        throw std::runtime_error("requires a degree-one polynomial");
    }

    std::vector<crypto_scalar_t> result(x.size() + 1, Crypto::ZERO);

    for (size_t i = 0; i < x.size(); ++i)
    {
        for (size_t j = 0; j < y.size(); ++j)
        {
            result[i + j] += x[i] * y[j];
        }
    }

    return result;
}

static inline arcturus_scalar_vector_t init_arcturus_scalar_vector(
    size_t d1,
    size_t d2,
    size_t d3,
    bool random = false,
    const crypto_scalar_t &initial_value = Crypto::ZERO)
{
    arcturus_scalar_vector_t result(d1);

    for (auto &level1 : result)
    {
        level1.resize(d2);

        for (auto &level2 : level1)
        {
            if (random)
            {
                level2 = Crypto::random_scalars(d3);
            }
            else
            {
                level2 = std::vector<crypto_scalar_t>(d3, initial_value);
            }
        }
    }

    return result;
}

namespace Crypto::RingSignature::Arcturus
{
    struct GrayCodeGenerator
    {
        GrayCodeGenerator(size_t N, size_t K, size_t v = -1): N(N), K(K), v(v)
        {
            g = std::vector<int>(K + 1, 0);

            u = std::vector<int>(K + 1, 1);

            changed.resize(1);

            changed[0] = {0, 0, 0};

            generate();
        }

        [[nodiscard]] std::vector<int> v_value() const
        {
            return v_changed;
        }

        [[nodiscard]] size_t size() const
        {
            return changed.size();
        }

        std::vector<int> operator[](int i) const
        {
            return changed[i];
        }

        [[nodiscard]] std::vector<std::vector<int>> values() const
        {
            return changed;
        }

      private:
        void generate()
        {
            const auto upper = size_t(crypto_scalar_t(N).pow(K).to_uint64_t()) - 1;

            for (size_t idx = 0; idx < upper; ++idx)
            {
                if (idx == v)
                {
                    v_changed = std::vector<int>(g.begin(), g.end() - 1);
                }

                int i = 0, k = g[0] + u[0];

                while (k >= N || k < 0)
                {
                    u[i] = u[i] * -1;

                    i += 1;

                    k = g[i] + u[i];
                }

                changed.push_back({i, g[i], k});

                g[i] = k;
            }
        }

        std::vector<std::vector<int>> changed;
        std::vector<int> v_changed;
        std::vector<int> g, u;
        size_t N = 0, K = 0, v = -1;
    };

    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_public_key_t> &public_keys,
        const std::vector<crypto_key_image_t> &key_images,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const std::vector<crypto_pedersen_commitment_t> &output_commitments,
        const crypto_arcturus_signature_t &signature)
    {
        if (public_keys.size() != input_commitments.size())
        {
            return false;
        }

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found)
        {
            return false;
        }

        if (m <= 1)
        {
            return false;
        }

        // check for commitment torsion
        for (const auto &commitment : input_commitments)
        {
            if (Crypto::INV_EIGHT * (Crypto::EIGHT * commitment) != commitment)
            {
                return false;
            }
        }

        for (const auto &commitment : output_commitments)
        {
            if (Crypto::INV_EIGHT * (Crypto::EIGHT * commitment) != commitment)
            {
                return false;
            }
        }

        if (signature.A == Crypto::Z || signature.B == Crypto::Z || signature.C == Crypto::Z
            || signature.D == Crypto::Z)
        {
            return false;
        }

        for (const auto &point : signature.X)
        {
            if (point == Crypto::Z)
            {
                return false;
            }
        }

        for (const auto &point : signature.Y)
        {
            if (point == Crypto::Z)
            {
                return false;
            }
        }

        for (const auto &point : signature.Z)
        {
            if (point == Crypto::Z)
            {
                return false;
            }
        }

        try
        {
            const size_t n = 2;

            auto tr = crypto_scalar_transcript_t(ARCTURUS_DOMAIN_0, message_digest);

            const auto w = key_images.size();

            auto f = init_arcturus_scalar_vector(w, m, n);

            tr.update(public_keys);

            tr.update(input_commitments);

            tr.update(output_commitments);

            tr.update(key_images);

            tr.update(signature.A);

            tr.update(signature.B);

            tr.update(signature.C);

            tr.update(signature.D);

            tr.update(signature.X);

            tr.update(signature.Y);

            tr.update(signature.Z);

            const auto x = tr.challenge();

            if (x == Crypto::ZERO)
            {
                return false;
            }

            auto w1 = Crypto::ZERO, w2 = Crypto::ZERO, w3 = Crypto::ZERO, w4 = Crypto::ZERO, w5 = Crypto::ZERO;

            while (w1 == Crypto::ZERO || w2 == Crypto::ZERO || w3 == Crypto::ZERO || w4 == Crypto::ZERO
                   || w5 == Crypto::ZERO)
            {
                w1 = Crypto::random_scalar();

                w2 = Crypto::random_scalar();

                w3 = Crypto::random_scalar();

                w4 = Crypto::random_scalar();

                w5 = Crypto::random_scalar();
            }

            auto scalars = crypto_scalar_vector_t();

            auto points = crypto_point_vector_t();

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t u = 0; u < w; ++u)
                {
                    f[u][j][0] = x;
                }

                for (size_t i = 1; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        f[u][j][i] = signature.f[u][j][i - 1];

                        f[u][j][0] -= f[u][j][i];
                    }
                }
            }

            auto fx = init_arcturus_scalar_vector(w, m, n);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 0; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        fx[u][j][i] = f[u][j][i] * (x - f[u][j][i]);
                    }
                }
            }

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 0; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        scalars.append((w1 * f[u][j][i]) + (w2 * fx[u][j][i]));

                        points.append(com_tensor_point(u, j, i));
                    }
                }
            }

            scalars.append((w1 * signature.zA) + (w2 * signature.zC));

            points.append(Crypto::H);

            scalars.append(w1.negate());

            points.append(signature.A);

            scalars.append(w1.negate() * x);

            points.append(signature.B);

            scalars.append(w2.negate() * x);

            points.append(signature.C);

            scalars.append(w2.negate());

            points.append(signature.D);

            auto U_scalar = Crypto::ZERO;

            auto tr_mu = crypto_scalar_transcript_t(ARCTURUS_DOMAIN_2);

            tr_mu.update(public_keys);

            tr_mu.update(input_commitments);

            tr_mu.update(output_commitments);

            tr_mu.update(key_images);

            tr_mu.update(signature.A);

            tr_mu.update(signature.B);

            tr_mu.update(signature.C);

            tr_mu.update(signature.D);

            const auto mu = tr_mu.challenge();

            if (mu == Crypto::ZERO)
            {
                return false;
            }

            std::vector<crypto_scalar_t> t(w, Crypto::ONE);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t u = 0; u < w; ++u)
                {
                    t[u] *= f[u][j][0];
                }
            }

            GrayCodeGenerator gray_codes(n, m);

            for (size_t k = 0; k < gray_codes.size(); ++k)
            {
                const auto &gray_update = gray_codes[k];

                if (k > 0)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        t[u] *= f[u][gray_update[0]][gray_update[1]].invert() * f[u][gray_update[0]][gray_update[2]];
                    }
                }

                auto sum_t = Crypto::ZERO;

                for (size_t u = 0; u < w; ++u)
                {
                    sum_t += t[u];
                }

                scalars.append(w3 * sum_t * mu.pow(k));

                points.append(public_keys[k]);

                scalars.append(w5 * sum_t);

                points.append(input_commitments[k]);

                U_scalar += w4 * sum_t * mu.pow(k);
            }

            scalars.append(U_scalar);

            points.append(Crypto::U);

            for (size_t j = 0; j < m; ++j)
            {
                scalars.append(w3.negate() * x.pow(j));

                points.append(signature.X[j]);

                scalars.append(w4.negate() * x.pow(j));

                points.append(signature.Y[j]);

                scalars.append(w5.negate() * x.pow(j));

                points.append(signature.Z[j]);
            }

            auto G_scalar = Crypto::ZERO;

            for (size_t u = 0; u < w; ++u)
            {
                G_scalar += signature.zR[u];

                scalars.append(w4.negate() * signature.zR[u]);

                points.append(key_images[u]);
            }

            scalars.append((w3.negate() * G_scalar) - (w5 * signature.zS));

            points.append(Crypto::G);

            for (const auto &output_commitment : output_commitments)
            {
                scalars.append(w5.negate() * x.pow(m));

                points.append(output_commitment);
            }

            return scalars.inner_product(points) == Crypto::Z;
        }
        catch (...)
        {
            return false;
        }
    }

    std::tuple<bool, crypto_arcturus_signature_t> complete_ring_signature(
        const std::vector<crypto_scalar_t> &signing_scalars,
        const crypto_scalar_t &x,
        const std::vector<std::vector<crypto_scalar_t>> &rho_R,
        const size_t &m,
        const crypto_arcturus_signature_t &signature,
        const std::vector<std::vector<crypto_scalar_t>> &partial_signing_scalars)
    {
        if (signature.zR.size() != signing_scalars.size())
        {
            return {false, {}};
        }

        try
        {
            for (const auto &scalar : signing_scalars)
            {
                SCALAR_OR_THROW(scalar);
            }

            SCALAR_OR_THROW(x);

            for (const auto &scalars : rho_R)
            {
                for (const auto &scalar : scalars)
                {
                    SCALAR_OR_THROW(scalar);
                }
            }
        }
        catch (...)
        {
            return {false, {}};
        }

        auto finalized_signature = signature;

        const auto w = signing_scalars.size();

        /**
         * If we have the full signing scalar (secret_ephemeral) then we can complete the signature quickly
         */
        try
        {
            if (partial_signing_scalars.empty())
            {
                for (size_t u = 0; u < signing_scalars.size(); ++u)
                {
                    finalized_signature.zR[u] *= signing_scalars[u] * x.pow(m);
                }
            }
            else /** Otherwise, we're using partial signing scalars (multisig) */
            {
                if (signing_scalars.size() != partial_signing_scalars.size())
                {
                    return {false, {}};
                }

                for (size_t u = 0; u < signing_scalars.size(); ++u)
                {
                    const auto &derivation_scalar = signing_scalars[u];

                    SCALAR_OR_THROW(derivation_scalar);

                    const auto &partial_scalars = partial_signing_scalars[u];

                    for (const auto &partial_scalar : partial_scalars)
                    {
                        SCALAR_OR_THROW(partial_scalar);
                    }

                    const auto partial_scalar = generate_partial_signing_scalar(m, x, derivation_scalar);

                    // create a copy of our partial signing scalars for computation and handling
                    crypto_scalar_vector_t keys(partial_scalars);

                    // add the partial scalar to the vector
                    keys.append(partial_scalar);

                    /**
                     * Remove any duplicate keys from the scalars that are being added together as we only use
                     * unique scalars when computing the resultant scalar
                     * p = [pk1 + pk2 + pk3 + ...] mod l
                     */
                    const auto derived_scalar = keys.dedupe_sort().sum();

                    finalized_signature.zR[u] *= derived_scalar;
                }
            }

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t u = 0; u < w; ++u)
                {
                    finalized_signature.zR[u] -= rho_R[u][j] * x.pow(j);
                }
            }

            return {true, finalized_signature};
        }
        catch (...)
        {
            return {false, {}};
        }
    }

    crypto_scalar_t generate_partial_signing_scalar(
        const size_t &m,
        const crypto_scalar_t &x,
        const crypto_secret_key_t &spend_secret_key)
    {
        if (m == 0)
        {
            throw std::invalid_argument("m must be greater than zero");
        }

        SCALAR_OR_THROW(x);

        SCALAR_OR_THROW(spend_secret_key);

        return x.pow(m) * spend_secret_key;
    }

    std::tuple<bool, crypto_arcturus_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_public_key_t> &public_keys,
        const std::vector<crypto_key_image_t> &key_images,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const std::vector<crypto_pedersen_commitment_t> &output_commitments,
        const std::vector<uint64_t> &real_output_indexes,
        const std::vector<crypto_secret_key_t> &secret_ephemerals,
        const std::vector<crypto_blinding_factor_t> &input_blinding_factors,
        const std::vector<crypto_blinding_factor_t> &output_blinding_factors,
        const std::vector<uint64_t> &input_amounts,
        const std::vector<uint64_t> &output_amounts)
    {
        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found)
        {
            return {false, {}};
        }

        const auto M = 1 << m;

        if (input_commitments.size() != M || real_output_indexes.size() != secret_ephemerals.size()
            || real_output_indexes.size() != input_blinding_factors.size()
            || real_output_indexes.size() != input_amounts.size())
        {
            return {false, {}};
        }

        const auto w = real_output_indexes.size();

        for (size_t u = 0; u < w; ++u)
        {
            if (public_keys[real_output_indexes[u]] != secret_ephemerals[u] * Crypto::G
                || input_commitments[real_output_indexes[u]]
                       != Crypto::RingCT::generate_pedersen_commitment(input_blinding_factors[u], input_amounts[u]))
            {
                return {false, {}};
            }
        }

        const auto [prep_success, x, rho_R, signature] = prepare_ring_signature(
            message_digest,
            public_keys,
            key_images,
            input_commitments,
            output_commitments,
            real_output_indexes,
            input_blinding_factors,
            output_blinding_factors,
            input_amounts,
            output_amounts);

        if (!prep_success)
        {
            return {false, {}};
        }

        return complete_ring_signature(secret_ephemerals, x, rho_R, m, signature);
    }

    std::tuple<bool, crypto_scalar_t, std::vector<std::vector<crypto_scalar_t>>, crypto_arcturus_signature_t>
        prepare_ring_signature(
            const crypto_hash_t &message_digest,
            const std::vector<crypto_public_key_t> &public_keys,
            const std::vector<crypto_key_image_t> &key_images,
            const std::vector<crypto_pedersen_commitment_t> &input_commitments,
            const std::vector<crypto_pedersen_commitment_t> &output_commitments,
            const std::vector<uint64_t> &real_output_indexes,
            const std::vector<crypto_blinding_factor_t> &input_blinding_factors,
            const std::vector<crypto_blinding_factor_t> &output_blinding_factors,
            const std::vector<uint64_t> &input_amounts,
            const std::vector<uint64_t> &output_amounts)
    {
        const size_t n = 2;

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found)
        {
            return {false, {}, {}, {}};
        }

        if (output_blinding_factors.size() != output_commitments.size()
            || output_blinding_factors.size() != output_amounts.size())
        {
            return {false, {}, {}, {}};
        }

        auto N = public_keys.size();

        const auto w = real_output_indexes.size();

        for (size_t j = 0; j < output_commitments.size(); ++j)
        {
            if (output_commitments[j]
                != Crypto::RingCT::generate_pedersen_commitment(output_blinding_factors[j], output_amounts[j]))
            {
                return {false, {}, {}, {}};
            }
        }

        try
        {
        retry:
            const auto rA = Crypto::random_scalar(), rB = Crypto::random_scalar(), rC = Crypto::random_scalar(),
                       rD = Crypto::random_scalar();

            auto a = init_arcturus_scalar_vector(w, m, n, true);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t u = 0; u < w; ++u)
                {
                    a[u][j][0] = Crypto::ZERO;

                    for (size_t i = 1; i < n; ++i)
                    {
                        a[u][j][0] -= a[u][j][i];
                    }
                }
            }

            const auto A = com_tensor(a, rA);

            std::vector<std::vector<int>> decomp_l;

            for (size_t u = 0; u < w; ++u)
            {
                const auto gray = GrayCodeGenerator(n, m, real_output_indexes[u]);

                decomp_l.push_back(gray.v_value());
            }

            auto sigma = init_arcturus_scalar_vector(w, m, n);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 0; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        sigma[u][j][i] = delta(decomp_l[u][j], i);
                    }
                };
            }

            const auto B = com_tensor(sigma, rB);

            auto a_sigma = init_arcturus_scalar_vector(w, m, n);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 0; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        a_sigma[u][j][i] = a[u][j][i] * (Crypto::ONE - Crypto::TWO * sigma[u][j][i]);
                    }
                }
            }

            const auto C = com_tensor(a_sigma, rC);

            auto a_sq = init_arcturus_scalar_vector(w, m, n);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 0; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        a_sq[u][j][i] = a[u][j][i].squared().negate();
                    }
                }
            }

            const auto D = com_tensor(a_sq, rD);

            auto p = init_arcturus_scalar_vector(w, N, 0);

            auto decomp_k = std::vector<int>(m, 0);

            GrayCodeGenerator gray_codes(n, m);

            for (size_t k = 0; k < gray_codes.size(); ++k)
            {
                const auto &gray_update = gray_codes[k];

                decomp_k[gray_update[0]] = gray_update[2];

                for (size_t u = 0; u < w; ++u)
                {
                    p[u][k] = {a[u][0][decomp_k[0]], delta(decomp_l[u][0], decomp_k[0])};
                }

                for (size_t j = 1; j < m; ++j)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        p[u][k] = convolve(p[u][k], {a[u][j][decomp_k[j]], delta(decomp_l[u][j], decomp_k[j])});
                    }
                }

                for (size_t j = 0; j < m; ++j)
                {
                    for (size_t u = 1; u < w; ++u)
                    {
                        p[0][k][j] += p[u][k][j];
                    }
                }
            }

            std::vector<crypto_point_t> X(m, Crypto::Z), Y(m, Crypto::Z), Z(m, Crypto::Z);

            auto tr = crypto_scalar_transcript_t(ARCTURUS_DOMAIN_2);

            tr.update(public_keys);

            tr.update(input_commitments);

            tr.update(output_commitments);

            tr.update(key_images);

            tr.update(A);

            tr.update(B);

            tr.update(C);

            tr.update(D);

            const auto mu = tr.challenge();

            if (mu == Crypto::ZERO)
            {
                goto retry;
            }

            std::vector<std::vector<crypto_scalar_t>> rho_R(w), rho_S(w);

            for (auto &level1 : rho_R)
            {
                level1 = Crypto::random_scalars(m);
            }

            for (auto &level1 : rho_S)
            {
                level1 = Crypto::random_scalars(m);
            }

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 0; i < N; ++i)
                {
                    X[j] += (p[0][i][j] * mu.pow(i)) * public_keys[i];

                    Y[j] += (mu.pow(i) * p[0][i][j]) * Crypto::U;

                    Z[j] += p[0][i][j] * input_commitments[i];
                }

                for (size_t u = 0; u < w; ++u)
                {
                    X[j] += rho_R[u][j] * Crypto::G;

                    Y[j] += rho_R[u][j] * key_images[u];

                    Z[j] += rho_S[u][j] * Crypto::G;
                }
            }

            crypto_arcturus_signature_t signature;

            signature.A = A;

            signature.B = B;

            signature.C = C;

            signature.D = D;

            signature.X = X;

            signature.Y = Y;

            signature.Z = Z;

            tr = crypto_scalar_transcript_t(ARCTURUS_DOMAIN_0, message_digest);

            tr.update(public_keys);

            tr.update(input_commitments);

            tr.update(output_commitments);

            tr.update(key_images);

            tr.update(A);

            tr.update(B);

            tr.update(C);

            tr.update(D);

            tr.update(X);

            tr.update(Y);

            tr.update(Z);

            const auto x = tr.challenge();

            if (x == Crypto::ZERO)
            {
                goto retry;
            }

            auto f = init_arcturus_scalar_vector(w, m, n - 1);

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t i = 1; i < n; ++i)
                {
                    for (size_t u = 0; u < w; ++u)
                    {
                        f[u][j][i - 1] = sigma[u][j][i] * x + a[u][j][i];
                    }
                }
            }

            const auto zA = rB * x + rA;

            const auto zC = rC * x + rD;

            std::vector<crypto_scalar_t> zR;

            auto zS = Crypto::ZERO;

            for (size_t u = 0; u < w; ++u)
            {
                zR.push_back(mu.pow(real_output_indexes[u]));

                zS += input_blinding_factors[u] * x.pow(m);
            }

            for (size_t j = 0; j < m; ++j)
            {
                for (size_t u = 0; u < w; ++u)
                {
                    zS -= rho_S[u][j] * x.pow(j);
                }
            }

            for (const auto &output_blinding_factor : output_blinding_factors)
            {
                zS -= output_blinding_factor * x.pow(m);
            }

            signature.f = f;

            signature.zA = zA;

            signature.zC = zC;

            signature.zR = zR;

            signature.zS = zS;

            return {true, x, rho_R, signature};
        }
        catch (...)
        {
            return {false, {}, {}, {}};
        }
    }
} // namespace Crypto::RingSignature::Arcturus
