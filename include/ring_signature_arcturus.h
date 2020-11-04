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

#ifndef CRYPTO_PROOFS_ARCTURUS_H
#define CRYPTO_PROOFS_ARCTURUS_H

#include "crypto_common.h"
#include "ringct.h"
#include "scalar_transcript.h"

struct crypto_arcturus_signature_t
{
    crypto_arcturus_signature_t() {}

    crypto_arcturus_signature_t(
        const crypto_point_t &A,
        const crypto_point_t &B,
        const crypto_point_t &C,
        const crypto_point_t &D,
        std::vector<crypto_point_t> X,
        std::vector<crypto_point_t> Y,
        std::vector<crypto_point_t> Z):
        A(A), B(B), C(C), D(D), X(std::move(X)), Y(std::move(Y)), Z(std::move(Z))
    {
    }

    JSON_OBJECT_CONSTRUCTORS(crypto_arcturus_signature_t, from_json)

    crypto_arcturus_signature_t(const std::string &input)
    {
        const auto string = Crypto::StringTools::from_hex(input);

        deserializer_t reader(string);

        deserialize(reader);
    }

    crypto_arcturus_signature_t(std::initializer_list<uint8_t> input)
    {
        std::vector<uint8_t> data(input);

        auto reader = deserializer_t(data);

        deserialize(reader);
    }

    crypto_arcturus_signature_t(const std::vector<uint8_t> &input)
    {
        deserializer_t reader(input);

        deserialize(reader);
    }

    crypto_arcturus_signature_t(deserializer_t &reader)
    {
        deserialize(reader);
    }

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(deserializer_t &reader)
    {
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
            const auto count = reader.varint<uint64_t>();

            Z.clear();

            for (size_t i = 0; i < count; ++i)
            {
                Z.push_back(reader.key<crypto_point_t>());
            }
        }

        deserialize_f(reader);

        zA = reader.key<crypto_scalar_t>();

        zC = reader.key<crypto_scalar_t>();

        {
            const auto count = reader.varint<uint64_t>();

            zR.clear();

            for (size_t i = 0; i < count; ++i)
            {
                zR.push_back(reader.key<crypto_scalar_t>());
            }
        }

        zS = reader.key<crypto_scalar_t>();
    }

    /**
     * Deserializes the f component of the structure
     * @param reader
     */
    void deserialize_f(deserializer_t &reader)
    {
        const auto level1_count = reader.varint<uint64_t>();

        f.clear();

        f.resize(level1_count);

        for (size_t i = 0; i < level1_count; ++i)
        {
            const auto level2_count = reader.varint<uint64_t>();

            f[i].resize(level2_count);

            for (size_t j = 0; j < level2_count; ++j)
            {
                const auto level3_count = reader.varint<uint64_t>();

                f[i][j].resize(level3_count);

                for (size_t k = 0; k < level3_count; ++k)
                {
                    f[i][j][k] = reader.key<crypto_scalar_t>();
                }
            }
        }
    }

    JSON_FROM_FUNC(from_json)
    {
        JSON_OBJECT_OR_THROW();

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

        JSON_MEMBER_OR_THROW("Z");

        Z.clear();

        for (const auto &elem : get_json_array(j, "Z"))
        {
            Z.emplace_back(get_json_string(elem));
        }

        JSON_MEMBER_OR_THROW("f");

        f.clear();

        for (const auto &level2 : get_json_array(j, "f"))
        {
            f.resize(f.size() + 1);

            auto &f1 = f.back();

            for (const auto &level3 : get_json_array(level2))
            {
                f1.resize(f1.size() + 1);

                auto &f2 = f1.back();

                for (const auto &elem : get_json_array(level3))
                {
                    f2.emplace_back(get_json_string(elem));
                }
            }
        }

        JSON_MEMBER_OR_THROW("zA");

        zA = get_json_string(j, "zA");

        JSON_MEMBER_OR_THROW("zC");

        zC = get_json_string(j, "zC");

        JSON_MEMBER_OR_THROW("zR");

        zR.clear();

        for (const auto &elem : get_json_array(j, "zR"))
        {
            zR.emplace_back(get_json_string(elem));
        }

        JSON_MEMBER_OR_THROW("zS");

        zS = get_json_string(j, "zS");
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
    void serialize(serializer_t &writer) const
    {
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

        writer.varint(Z.size());

        for (const auto &val : Z)
        {
            writer.key(val);
        }

        serialize_f(writer);

        writer.key(zA);

        writer.key(zC);

        writer.varint(zR.size());

        for (const auto &val : zR)
        {
            writer.key(val);
        }

        writer.key(zS);
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
     * Serializes the f component of the structure
     * @return
     */
    void serialize_f(serializer_t &writer) const
    {
        writer.varint(f.size());

        for (const auto &level2 : f)
        {
            writer.varint(level2.size());

            for (const auto &level3 : level2)
            {
                writer.varint(level3.size());

                for (const auto &val : level3)
                {
                    writer.key(val);
                }
            }
        }
    }

    /**
     * Serializes the f component of the structure
     * @return
     */
    [[nodiscard]] std::vector<uint8_t> serialize_f() const
    {
        serializer_t writer;

        serialize_f(writer);

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

            writer.Key("Z");
            writer.StartArray();
            {
                for (const auto &val : Z)
                {
                    val.toJSON(writer);
                }
            }
            writer.EndArray();

            writer.Key("f");
            writer.StartArray();
            {
                for (const auto &level2 : f)
                {
                    writer.StartArray();
                    {
                        for (const auto &level3 : level2)
                        {
                            writer.StartArray();
                            {
                                for (const auto &val : level3)
                                {
                                    val.toJSON(writer);
                                }
                            }
                            writer.EndArray();
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

            writer.Key("zR");
            writer.StartArray();
            {
                for (const auto &val : zR)
                {
                    val.toJSON(writer);
                }
            }
            writer.EndArray();

            writer.Key("zS");
            zS.toJSON(writer);
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

    std::vector<crypto_point_t> X, Y, Z;
    crypto_point_t A, B, C, D;
    std::vector<std::vector<std::vector<crypto_scalar_t>>> f;
    std::vector<crypto_scalar_t> zR;
    crypto_scalar_t zA, zC, zS;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_arcturus_signature_t &value)
    {
        os << "Arcturus Signature" << std::endl;

        os << "A: " << value.A << std::endl
           << "B: " << value.B << std::endl
           << "C: " << value.C << std::endl
           << "D: " << value.D << std::endl;

        os << "X: " << std::endl;
        for (const auto &val : value.X)
        {
            os << "\t" << val << std::endl;
        }
        os << std::endl;

        os << "Y: " << std::endl;
        for (const auto &val : value.Y)
        {
            os << "\t" << val << std::endl;
        }
        os << std::endl;

        os << "Z: " << std::endl;
        for (const auto &val : value.Z)
        {
            os << "\t" << val << std::endl;
        }
        os << std::endl;

        os << "f: " << std::endl;
        for (const auto &level1 : value.f)
        {
            for (const auto &level2 : level1)
            {
                for (const auto &val : level2)
                {
                    os << "\t\t" << val << std::endl;
                }

                os << std::endl;
            }
        }

        os << "zA: " << value.zA << std::endl << "zC: " << value.zC << std::endl;

        os << "zR: " << std::endl;
        for (const auto &val : value.zR)
        {
            os << "\t" << val << std::endl;
        }
        os << std::endl;

        os << "zS: " << value.zS << std::endl;

        return os;
    }
} // namespace std

namespace Crypto::RingSignature::Arcturus
{
    /**
     * Checks the Arcturus "ring signature" presented
     * @param message_digest
     * @param public_keys
     * @param key_images
     * @param input_commitments
     * @param output_commitments
     * @param signature
     * @return
     */
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_public_key_t> &public_keys,
        const std::vector<crypto_key_image_t> &key_images,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const std::vector<crypto_pedersen_commitment_t> &output_commitments,
        const crypto_arcturus_signature_t &signature);

    /**
     * Completes the prepared Arcturus "ring signature"
     * @param signing_scalars
     * @param x
     * @param rho_R
     * @param m
     * @param signature
     * @param partial_signing_scalars
     * @return
     */
    std::tuple<bool, crypto_arcturus_signature_t> complete_ring_signature(
        const std::vector<crypto_scalar_t> &signing_scalars,
        const crypto_scalar_t &x,
        const std::vector<std::vector<crypto_scalar_t>> &rho_R,
        const size_t &m,
        const crypto_arcturus_signature_t &signature,
        const std::vector<std::vector<crypto_scalar_t>> &partial_signing_scalars = {});

    /**
     * Generates a partial signing scalar that is a factor of the full signing scalar and typically
     * used by multisig wallets -- input data is supplied from prepare_ring_signature
     * @param m
     * @param x
     * @param spend_secret_key
     * @return
     */
    crypto_scalar_t generate_partial_signing_scalar(
        const size_t &m,
        const crypto_scalar_t &x,
        const crypto_secret_key_t &spend_secret_key);

    /**
     * Generates an Arcturus "ring signature" using the secrets provided
     * @param message_digest
     * @param public_keys
     * @param key_images
     * @param input_commitments
     * @param output_commitments
     * @param real_output_indexes
     * @param secret_ephemerals
     * @param input_blinding_factors
     * @param output_blinding_factors
     * @param input_amounts
     * @param output_amounts
     * @return
     */
    std::tuple<bool, crypto_arcturus_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_public_key_t> &public_keys, // M
        const std::vector<crypto_key_image_t> &key_images,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments, // P
        const std::vector<crypto_pedersen_commitment_t> &output_commitments, // Q
        const std::vector<uint64_t> &real_output_indexes, // l
        const std::vector<crypto_secret_key_t> &secret_ephemerals, // r
        const std::vector<crypto_blinding_factor_t> &input_blinding_factors, // s
        const std::vector<crypto_blinding_factor_t> &output_blinding_factors, // t
        const std::vector<uint64_t> &input_amounts, // a
        const std::vector<uint64_t> &output_amounts // b
    );

    /**
     * Prepares an Arcturus "ring signature" using the primitive values provided
     * Must be completed via complete_ring_signature before it will validate
     * @param message_digest
     * @param public_keys
     * @param key_images
     * @param input_commitments
     * @param output_commitments
     * @param real_output_indexes
     * @param input_blinding_factors
     * @param output_blinding_factors
     * @param input_amounts
     * @param output_amounts
     * @return
     */
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
            const std::vector<uint64_t> &output_amounts);
} // namespace Crypto::RingSignature::Arcturus

#endif // CRYPTO_PROOFS_ARCTURUS_H
