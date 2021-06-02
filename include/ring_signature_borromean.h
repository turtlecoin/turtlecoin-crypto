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

#ifndef CRYPTO_RING_SIGNATURE_BORROMEAN_H
#define CRYPTO_RING_SIGNATURE_BORROMEAN_H

#include "crypto_common.h"
#include "hashing.h"

struct crypto_borromean_signature_t
{
    crypto_borromean_signature_t() {}

    crypto_borromean_signature_t(std::vector<crypto_signature_t> signatures): signatures(std::move(signatures)) {}

    JSON_OBJECT_CONSTRUCTORS(crypto_borromean_signature_t, from_json);

    crypto_borromean_signature_t(const std::string &input)
    {
        const auto string = Crypto::StringTools::from_hex(input);

        deserializer_t reader(string);

        deserialize(reader);
    }

    crypto_borromean_signature_t(std::initializer_list<uint8_t> input)
    {
        std::vector<uint8_t> data(input);

        deserializer_t reader(data);

        deserialize(reader);
    }

    crypto_borromean_signature_t(const std::vector<uint8_t> &input)
    {
        deserializer_t reader(input);

        deserialize(reader);
    }

    crypto_borromean_signature_t(deserializer_t &reader)
    {
        deserialize(reader);
    }

    /**
     * Checks that the basic construction of the proof is valid
     * @param ring_size
     * @return
     */
    [[nodiscard]] bool check_construction(size_t ring_size) const
    {
        if (signatures.size() != ring_size)
        {
            return false;
        }

        for (const auto &signature : signatures)
        {
            if (!signature.LR.L.valid() || !signature.LR.R.valid())
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(deserializer_t &reader)
    {
        {
            const auto count = reader.varint<uint64_t>();

            signatures.clear();

            for (size_t i = 0; i < count; ++i)
            {
                signatures.push_back(reader.key<crypto_signature_t>());
            }
        }
    }

    JSON_FROM_FUNC(from_json)
    {
        JSON_OBJECT_OR_THROW();

        JSON_MEMBER_OR_THROW("signatures");

        signatures.clear();

        for (const auto &elem : get_json_array(j, "signatures"))
        {
            signatures.emplace_back(get_json_string(elem));
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
     * @param writer
     */
    void serialize(serializer_t &writer) const
    {
        writer.varint(signatures.size());

        for (const auto &val : signatures)
        {
            writer.key(val);
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
            writer.Key("signatures");
            writer.StartArray();
            {
                for (const auto &val : signatures)
                {
                    val.toJSON(writer);
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

    std::vector<crypto_signature_t> signatures;
};

namespace Crypto::RingSignature::Borromean
{
    /**
     * Checks the Borromean ring signature presented
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     * @return
     */
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_borromean_signature_t &borromean_signature);

    /**
     * Completes the prepared Borromean ring signature
     * @param signing_scalar
     * @param real_output_index
     * @param alpha_scalar
     * @param signature
     * @param partial_signing_scalars
     * @return
     */
    std::tuple<bool, crypto_borromean_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        size_t real_output_index,
        const crypto_borromean_signature_t &borromean_signature,
        const std::vector<crypto_scalar_t> &partial_signing_scalars = {});

    /**
     * Generates a partial signing scalar that is a factor of a full signing scalar and typically
     * used by multisig wallets -- input data is supplied from prepare_ring_signature
     * @param real_output_index
     * @param signature
     * @param spend_secret_key
     * @return
     */
    crypto_scalar_t generate_partial_signing_scalar(
        size_t real_output_index,
        const crypto_borromean_signature_t &borromean_signature,
        const crypto_secret_key_t &spend_secret_key);

    /**
     * Generates Borromean ring signature using the secret key provided
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     * @return
     */
    std::tuple<bool, crypto_borromean_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_secret_key_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys);

    /**
     * Prepares a Borromean ring signature using the primitive values provided
     * Must be completed via complete_ring_signature before it will validate
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     * @param alpha_scalar
     * @return
     */
    std::tuple<bool, crypto_borromean_signature_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index);
} // namespace Crypto::RingSignature::Borromean

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_borromean_signature_t &value)
    {
        os << "Borromean [" << value.size() << " bytes]:" << std::endl << "\tsignatures:" << std::endl;

        for (const auto &val : value.signatures)
        {
            os << "\t\t" << val << std::endl;
        }

        return os;
    }
} // namespace std

#endif // CRYPTO_RING_SIGNATURE_BORROMEAN_H
