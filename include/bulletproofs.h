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
// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet

#ifndef CRYPTO_RANGEPROOFS_BULLETPROOFS_H
#define CRYPTO_RANGEPROOFS_BULLETPROOFS_H

#include "crypto_common.h"

/**
 * A Bulletproof Range Proof
 */
struct crypto_bulletproof_t : ISerializable
{
    crypto_bulletproof_t() {}

    crypto_bulletproof_t(
        const crypto_point_t &A,
        const crypto_point_t &S,
        const crypto_point_t &T1,
        const crypto_point_t &T2,
        const crypto_scalar_t &taux,
        const crypto_scalar_t &mu,
        std::vector<crypto_point_t> L,
        std::vector<crypto_point_t> R,
        const crypto_scalar_t &g,
        const crypto_scalar_t &h,
        const crypto_scalar_t &t):
        A(A), S(S), T1(T1), T2(T2), taux(taux), mu(mu), L(std::move(L)), R(std::move(R)), g(g), h(h), t(t)
    {
    }

    JSON_OBJECT_CONSTRUCTORS(crypto_bulletproof_t, fromJSON)

    crypto_bulletproof_t(const std::string &input)
    {
        const auto string = Crypto::StringTools::from_hex(input);

        deserializer_t reader(string);

        deserialize(reader);
    }

    crypto_bulletproof_t(std::initializer_list<uint8_t> input)
    {
        std::vector<uint8_t> data(input);

        deserializer_t reader(data);

        deserialize(reader);
    }

    crypto_bulletproof_t(const std::vector<uint8_t> &input)
    {
        deserializer_t reader(input);

        deserialize(reader);
    }

    crypto_bulletproof_t(deserializer_t &reader)
    {
        deserialize(reader);
    }

    /**
     * Checks that the basic construction of the proof is valid
     * @return
     */
    [[nodiscard]] bool check_construction() const
    {
        if (L.size() != R.size() || L.empty())
        {
            return false;
        }

        if (!A.valid() || !S.valid() || !T1.valid() || !T2.valid())
        {
            return false;
        }

        for (const auto &point : L)
        {
            if (!point.valid())
            {
                return false;
            }
        }

        for (const auto &point : R)
        {
            if (!point.valid())
            {
                return false;
            }
        }

        if (!taux.valid() || !mu.valid() || !g.valid() || !h.valid() || !t.valid())
        {
            return false;
        }

        return true;
    }

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(deserializer_t &reader) override
    {
        A = reader.key<crypto_point_t>();

        S = reader.key<crypto_point_t>();

        T1 = reader.key<crypto_point_t>();

        T2 = reader.key<crypto_point_t>();

        taux = reader.key<crypto_scalar_t>();

        mu = reader.key<crypto_scalar_t>();

        L = reader.keyV<crypto_point_t>();

        R = reader.keyV<crypto_point_t>();

        g = reader.key<crypto_scalar_t>();

        h = reader.key<crypto_scalar_t>();

        t = reader.key<crypto_scalar_t>();
    }

    JSON_FROM_FUNC(fromJSON) override
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(A)

        LOAD_KEY_FROM_JSON(S)

        LOAD_KEY_FROM_JSON(T1)

        LOAD_KEY_FROM_JSON(T2)

        LOAD_KEY_FROM_JSON(taux)

        LOAD_KEY_FROM_JSON(mu)

        LOAD_KEYV_FROM_JSON(L)

        LOAD_KEYV_FROM_JSON(R)

        LOAD_KEY_FROM_JSON(g)

        LOAD_KEY_FROM_JSON(h)

        LOAD_KEY_FROM_JSON(t)
    }

    /**
     * Provides the hash of the serialized structure
     * @return
     */
    [[nodiscard]] crypto_hash_t hash() const
    {
        const auto serialized = serialize();

        return Crypto::Hashing::sha3(serialized.data(), serialized.size());
    }

    /**
     * Serializes the struct to a byte array
     * @param writer
     */
    void serialize(serializer_t &writer) const override
    {
        writer.key(A);

        writer.key(S);

        writer.key(T1);

        writer.key(T2);

        writer.key(taux);

        writer.key(mu);

        writer.key(L);

        writer.key(R);

        writer.key(g);

        writer.key(h);

        writer.key(t);
    }

    /**
     * Serializes the struct to a byte array
     * @return
     */
    [[nodiscard]] std::vector<uint8_t> serialize() const override
    {
        serializer_t writer;

        serialize(writer);

        return writer.vector();
    }

    /**
     * Returns the serialized byte size
     * @return
     */
    [[nodiscard]] size_t size() const override
    {
        return serialize().size();
    }

    /**
     * Writes the structure as JSON to the provided writer
     * @param writer
     */
    JSON_TO_FUNC(toJSON) override
    {
        writer.StartObject();
        {
            KEY_TO_JSON(A);

            KEY_TO_JSON(S);

            KEY_TO_JSON(T1);

            KEY_TO_JSON(T2);

            KEY_TO_JSON(taux);

            KEY_TO_JSON(mu);

            KEYV_TO_JSON(L);

            KEYV_TO_JSON(R);

            KEY_TO_JSON(g);

            KEY_TO_JSON(h);

            KEY_TO_JSON(t);
        }
        writer.EndObject();
    }

    /**
     * Returns the hex encoded serialized byte array
     * @return
     */
    [[nodiscard]] std::string to_string() const override
    {
        const auto bytes = serialize();

        return Crypto::StringTools::to_hex(bytes.data(), bytes.size());
    }

    crypto_point_t A, S, T1, T2;
    crypto_scalar_t taux, mu;
    std::vector<crypto_point_t> L, R;
    crypto_scalar_t g, h, t;
};

namespace Crypto::RangeProofs::Bulletproofs
{
    /**
     * Generates a Bulletproof range proof and the related pedersen commitments
     * for the given amounts and blinding factors
     * @param amounts
     * @param blinding_factors
     * @param N the number of bits (2^n) to prove
     * @return {proof, commitments}
     */
    std::tuple<crypto_bulletproof_t, std::vector<crypto_pedersen_commitment_t>> prove(
        const std::vector<uint64_t> &amounts,
        const std::vector<crypto_blinding_factor_t> &blinding_factors,
        size_t N = 64);

    /**
     * Performs batch verification of the range proofs provided for the provided
     * pedersen commitments to the given values
     * @param proofs
     * @param commitments[]
     * @param N the number of bits (2^n) to prove
     * @return
     */
    bool verify(
        const std::vector<crypto_bulletproof_t> &proofs,
        const std::vector<std::vector<crypto_pedersen_commitment_t>> &commitments,
        size_t N = 64);

    /**
     * Performs verification of the range proof provided for the provided
     * pedersen commitments to the given values
     * @param proof
     * @param commitments
     * @param N the number of bits (2^n) to prove
     * @return
     */
    bool verify(
        const crypto_bulletproof_t &proof,
        const std::vector<crypto_pedersen_commitment_t> &commitments,
        size_t N = 64);
} // namespace Crypto::RangeProofs::Bulletproofs

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_bulletproof_t &value)
    {
        os << "Bulletproof [" << value.size() << " bytes]:" << std::endl
           << "\tA: " << value.A << std::endl
           << "\tS: " << value.S << std::endl
           << "\tT1: " << value.T1 << std::endl
           << "\tT2: " << value.T2 << std::endl
           << "\ttaux: " << value.taux << std::endl
           << "\tmu: " << value.mu << std::endl
           << "\tL:" << std::endl;

        for (const auto &val : value.L)
        {
            os << "\t\t" << val << std::endl;
        }

        os << "\tR:" << std::endl;

        for (const auto &val : value.R)
        {
            os << "\t\t" << val << std::endl;
        }

        os << "\tg: " << value.g << std::endl << "\th: " << value.h << std::endl << "\tt: " << value.t << std::endl;

        return os;
    }
} // namespace std

#endif // CRYPTO_RANGEPROOFS_BULLETPROOFS_H
