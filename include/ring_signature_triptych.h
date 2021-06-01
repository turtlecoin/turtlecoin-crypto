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

#include <utility>

struct crypto_triptych_signature_t
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

    JSON_OBJECT_CONSTRUCTORS(crypto_triptych_signature_t, from_json)

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
        if (!commitment_image.check_subgroup())
        {
            return false;
        }

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

        if (!Crypto::check_torsion(pseudo_commitment))
        {
            return false;
        }

        return true;
    }

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(deserializer_t &reader)
    {
        commitment_image = reader.key<crypto_key_image_t>();

        pseudo_commitment = reader.key<crypto_pedersen_commitment_t>();

        A = reader.key<crypto_point_t>();

        B = reader.key<crypto_point_t>();

        C = reader.key<crypto_point_t>();

        D = reader.key<crypto_point_t>();

        {
            const auto count = reader.varint<uint64_t>();

            X.clear();

            for (size_t i = 0; i < count; ++i)
            {
                X.push_back(reader.key<crypto_point_t>());
            }
        }

        {
            const auto count = reader.varint<uint64_t>();

            Y.clear();

            for (size_t i = 0; i < count; ++i)
            {
                Y.push_back(reader.key<crypto_point_t>());
            }
        }

        {
            const auto level1_count = reader.varint<uint64_t>();

            f.clear();

            f.resize(level1_count);

            for (size_t i = 0; i < level1_count; ++i)
            {
                const auto count = reader.varint<uint64_t>();

                for (size_t j = 0; j < count; ++j)
                {
                    f[i].push_back(reader.key<crypto_scalar_t>());
                }
            }
        }

        zA = reader.key<crypto_scalar_t>();

        zC = reader.key<crypto_scalar_t>();

        z = reader.key<crypto_scalar_t>();

        {
            const auto count = reader.varint<uint64_t>();

            offsets.clear();

            for (size_t i = 0; i < count; ++i)
            {
                offsets.push_back(reader.varint<uint64_t>());
            }
        }
    }

    JSON_FROM_FUNC(from_json)
    {
        JSON_OBJECT_OR_THROW();

        JSON_MEMBER_OR_THROW("commitment_image");

        commitment_image = get_json_string(j, "commitment_image");

        JSON_MEMBER_OR_THROW("pseudo_commitment");

        pseudo_commitment = get_json_string(j, "pseudo_commitment");

        JSON_MEMBER_OR_THROW("A");

        A = get_json_string(j, "A");

        JSON_MEMBER_OR_THROW("B");

        B = get_json_string(j, "B");

        JSON_MEMBER_OR_THROW("C");

        C = get_json_string(j, "C");

        JSON_MEMBER_OR_THROW("D");

        D = get_json_string(j, "D");

        JSON_MEMBER_OR_THROW("X");

        X.clear();

        for (const auto &elem : get_json_array(j, "X"))
        {
            X.emplace_back(get_json_string(elem));
        }

        JSON_MEMBER_OR_THROW("Y");

        Y.clear();

        for (const auto &elem : get_json_array(j, "Y"))
        {
            Y.emplace_back(get_json_string(elem));
        }

        JSON_MEMBER_OR_THROW("f");

        f.clear();

        for (const auto &level1 : get_json_array(j, "f"))
        {
            f.resize(f.size() + 1);

            auto &f1 = f.back();

            for (const auto &elem : get_json_array(level1))
            {
                f1.emplace_back(get_json_string(elem));
            }
        }

        JSON_MEMBER_OR_THROW("zA");

        zA = get_json_string(j, "zA");

        JSON_MEMBER_OR_THROW("zC");

        zC = get_json_string(j, "zC");

        JSON_MEMBER_OR_THROW("z");

        z = get_json_string(j, "z");

        JSON_MEMBER_OR_THROW("offsets");

        offsets.clear();

        for (const auto &elem : get_json_array(j, "offsets"))
        {
            offsets.emplace_back(get_json_uint64_t(elem));
        }
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
    void serialize(serializer_t &writer) const
    {
        writer.key(commitment_image);

        writer.key(pseudo_commitment);

        writer.key(A);

        writer.key(B);

        writer.key(C);

        writer.key(D);

        writer.varint(X.size());

        for (const auto &val : X)
        {
            writer.key(val);
        }

        writer.varint(Y.size());

        for (const auto &val : Y)
        {
            writer.key(val);
        }

        writer.varint(f.size());

        for (const auto &level1 : f)
        {
            writer.varint(level1.size());

            for (const auto &val : level1)
            {
                writer.key(val);
            }
        }

        writer.key(zA);

        writer.key(zC);

        writer.key(z);

        writer.varint(offsets.size());

        for (const auto &val : offsets)
        {
            writer.varint(val);
        }
    }

    /**
     * Serializes the struct to a byte array
     * @return
     */
    [[nodiscard]] std::vector<uint8_t> serialize() const
    {
        serializer_t writer;

        serialize(writer);

        return writer.vector();
    }

    /**
     * Returns the serialized byte size
     * @return
     */
    [[nodiscard]] size_t size() const
    {
        return serialize().size();
    }

    /**
     * Writes the structure as JSON to the provided writer
     * @param writer
     */
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
    {
        writer.StartObject();
        {
            writer.Key("commitment_image");
            commitment_image.toJSON(writer);

            writer.Key("pseudo_commitment");
            pseudo_commitment.toJSON(writer);

            writer.Key("A");
            A.toJSON(writer);

            writer.Key("B");
            B.toJSON(writer);

            writer.Key("C");
            C.toJSON(writer);

            writer.Key("D");
            D.toJSON(writer);

            writer.Key("X");
            writer.StartArray();
            {
                for (const auto &val : X)
                {
                    val.toJSON(writer);
                }
            }
            writer.EndArray();

            writer.Key("Y");
            writer.StartArray();
            {
                for (const auto &val : Y)
                {
                    val.toJSON(writer);
                }
            }
            writer.EndArray();

            writer.Key("f");
            writer.StartArray();
            {
                for (const auto &level1 : f)
                {
                    writer.StartArray();
                    {
                        for (const auto &val : level1)
                        {
                            val.toJSON(writer);
                        }
                    }
                    writer.EndArray();
                }
            }
            writer.EndArray();

            writer.Key("zA");
            zA.toJSON(writer);

            writer.Key("zC");
            zC.toJSON(writer);

            writer.Key("z");
            z.toJSON(writer);

            writer.Key("offsets");
            writer.StartArray();
            {
                for (const auto &val : offsets)
                {
                    writer.Uint64(val);
                }
            }
            writer.EndArray();
        }
        writer.EndObject();
    }

    /**
     * Returns the hex encoded serialized byte array
     * @return
     */
    [[nodiscard]] std::string to_string() const
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
    std::vector<uint64_t> offsets;
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
           << "\tcommitment_image: " << value.commitment_image << std::endl
           << "\tpseudo_commitment: " << value.pseudo_commitment << std::endl
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

        for (const auto &val : value.X)
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
           << "\tOffsets:" << std::endl;

        for (const auto &val : value.offsets)
        {
            os << "\t\t" << std::to_string(val) << std::endl;
        }

        return os;
    }
} // namespace std
#endif // CRYPTO_PROOFS_TRIPTYCH_H
