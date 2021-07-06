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

#ifndef CRYPTO_PROOFS_TRIPTYCH_H
#define CRYPTO_PROOFS_TRIPTYCH_H

#include "crypto_common.h"
#include "hashing.h"

struct crypto_triptych_signature_t : ISerializable
{
    crypto_triptych_signature_t() {}

    crypto_triptych_signature_t(
        const crypto_key_image_t &commitment_image,
        const crypto_pedersen_commitment_t &pseudo_commitment,
        const crypto_point_t &A,
        const crypto_point_t &B,
        const crypto_point_t &C,
        const crypto_point_t &D,
        std::vector<crypto_point_t> X,
        std::vector<crypto_point_t> Y,
        std::vector<std::vector<crypto_scalar_t>> f,
        const crypto_scalar_t &zA,
        const crypto_scalar_t &zC,
        const crypto_scalar_t &z):
        commitment_image(commitment_image),
        pseudo_commitment(pseudo_commitment),
        A(A),
        B(B),
        C(C),
        D(D),
        X(std::move(X)),
        Y(std::move(Y)),
        f(std::move(f)),
        zA(zA),
        zC(zC),
        z(z)
    {
    }

    JSON_OBJECT_CONSTRUCTORS(crypto_triptych_signature_t, fromJSON)

    crypto_triptych_signature_t(const std::string &input)
    {
        const auto string = Crypto::StringTools::from_hex(input);

        deserializer_t reader(string);

        deserialize(reader);
    }

    crypto_triptych_signature_t(std::initializer_list<uint8_t> input)
    {
        std::vector<uint8_t> data(input);

        deserializer_t reader(data);

        deserialize(reader);
    }

    crypto_triptych_signature_t(const std::vector<uint8_t> &input)
    {
        deserializer_t reader(input);

        deserialize(reader);
    }

    crypto_triptych_signature_t(deserializer_t &reader)
    {
        deserialize(reader);
    }

    /**
     * Checks that the basic construction of the proof is valid
     * @param m
     * @param n
     * @return
     */
    [[nodiscard]] bool check_construction(size_t m, size_t n = 2) const
    {
        if (!A.valid() || !B.valid() || !C.valid() || !D.valid())
        {
            return false;
        }

        if (X.size() != m || Y.size() != m || f.size() != m)
        {
            return false;
        }

        for (const auto &point : X)
        {
            if (!point.valid())
            {
                return false;
            }
        }

        for (const auto &point : Y)
        {
            if (!point.valid())
            {
                return false;
            }
        }

        if (!zA.valid() || !zC.valid() || !z.valid())
        {
            return false;
        }

        for (const auto &level1 : f)
        {
            if (level1.size() != n - 1)
            {
                return false;
            }

            for (const auto &scalar : level1)
            {
                if (!scalar.valid())
                {
                    return false;
                }
            }
        }

        if (!commitment_image.check_subgroup())
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

        B = reader.key<crypto_point_t>();

        C = reader.key<crypto_point_t>();

        D = reader.key<crypto_point_t>();

        X = reader.keyV<crypto_point_t>();

        Y = reader.keyV<crypto_point_t>();

        f = reader.keyVV<crypto_scalar_t>();

        zA = reader.key<crypto_scalar_t>();

        zC = reader.key<crypto_scalar_t>();

        z = reader.key<crypto_scalar_t>();

        commitment_image = reader.key<crypto_key_image_t>();

        pseudo_commitment = reader.key<crypto_pedersen_commitment_t>();
    }

    JSON_FROM_FUNC(fromJSON) override
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(A)

        LOAD_KEY_FROM_JSON(B)

        LOAD_KEY_FROM_JSON(C)

        LOAD_KEY_FROM_JSON(D)

        LOAD_KEYV_FROM_JSON(X)

        LOAD_KEYV_FROM_JSON(Y)

        LOAD_KEYVV_FROM_JSON(f)

        LOAD_KEY_FROM_JSON(zA)

        LOAD_KEY_FROM_JSON(zC)

        LOAD_KEY_FROM_JSON(z)

        LOAD_KEY_FROM_JSON(commitment_image)

        LOAD_KEY_FROM_JSON(pseudo_commitment)
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
     * @return
     */
    void serialize(serializer_t &writer) const override
    {
        writer.key(A);

        writer.key(B);

        writer.key(C);

        writer.key(D);

        writer.key(X);

        writer.key(Y);

        writer.key(f);

        writer.key(zA);

        writer.key(zC);

        writer.key(z);

        writer.key(commitment_image);

        writer.key(pseudo_commitment);
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

            KEY_TO_JSON(B);

            KEY_TO_JSON(C);

            KEY_TO_JSON(D);

            KEYV_TO_JSON(X);

            KEYV_TO_JSON(Y);

            KEYVV_TO_JSON(f);

            KEY_TO_JSON(zA);

            KEY_TO_JSON(zC);

            KEY_TO_JSON(z);

            KEY_TO_JSON(commitment_image);

            KEY_TO_JSON(pseudo_commitment);
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

    crypto_key_image_t commitment_image;
    crypto_pedersen_commitment_t pseudo_commitment;
    crypto_point_t A, B, C, D;
    std::vector<crypto_point_t> X, Y;
    std::vector<std::vector<crypto_scalar_t>> f;
    crypto_scalar_t zA, zC, z;
};

namespace Crypto::RingSignature::Triptych
{
    /**
     * Checks the Triptych proof presented
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     * @param commitments
     * @return
     */
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_triptych_signature_t &signature,
        const std::vector<crypto_pedersen_commitment_t> &commitments);

    /**
     * Completes the prepared Triptych proof
     * @param signing_scalar
     * @param signature
     * @param xpow
     * @param partial_signing_scalars
     * @return
     */
    std::tuple<bool, crypto_triptych_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        const crypto_triptych_signature_t &signature,
        const crypto_scalar_t &xpow,
        const std::vector<crypto_scalar_t> &partial_signing_scalars = {});

    /**
     * Generates a partial signing scalar that is a factor of a full signing scalar and typically
     * used by multisig wallets -- input data is supplied from prepare_ring_signature
     * @param spend_secret_key
     * @param xpow
     * @return
     */
    crypto_scalar_t
        generate_partial_signing_scalar(const crypto_scalar_t &spend_secret_key, const crypto_scalar_t &xpow);

    /**
     * Generates a Triptych proof using the secrets provided
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     * @param input_blinding_factor
     * @param input_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     * @return
     */
    std::tuple<bool, crypto_triptych_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_secret_key_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment);

    /**
     * Prepares a Triptych proof using the primitive values provided
     * Must be completed via complete_ring_signature before it will validate
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     * @param input_blinding_factor
     * @param input_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     * @return
     */
    std::tuple<bool, crypto_triptych_signature_t, crypto_scalar_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment);
} // namespace Crypto::RingSignature::Triptych

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_triptych_signature_t &value)
    {
        os << "Triptych [" << value.size() << " bytes]:" << std::endl
           << "\tA: " << value.A << std::endl
           << "\tB: " << value.B << std::endl
           << "\tC: " << value.C << std::endl
           << "\tD: " << value.D << std::endl
           << "\tX:" << std::endl;

        for (const auto &val : value.X)
        {
            os << "\t\t" << val << std::endl;
        }
        os << std::endl;

        os << "\tY:" << std::endl;

        for (const auto &val : value.Y)
        {
            os << "\t\t" << val << std::endl;
        }
        os << std::endl;

        os << "\tf:" << std::endl;
        for (const auto &level1 : value.f)
        {
            for (const auto &val : level1)
            {
                os << "\t\t" << val << std::endl;
            }

            os << std::endl;
        }
        os << std::endl;

        os << "\tzA: " << value.zA << std::endl
           << "\tzC: " << value.zC << std::endl
           << "\tz: " << value.z << std::endl
           << "\tcommitment_image: " << value.commitment_image << std::endl
           << "\tpseudo_commitment: " << value.pseudo_commitment << std::endl;

        return os;
    }
} // namespace std
#endif // CRYPTO_PROOFS_TRIPTYCH_H
