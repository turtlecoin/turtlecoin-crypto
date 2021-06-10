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
// Inspired by the work of Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/clsag

#ifndef CRYPTO_RING_SIGNATURE_CLSAG_H
#define CRYPTO_RING_SIGNATURE_CLSAG_H

#include "crypto_common.h"
#include "hashing.h"

struct crypto_clsag_signature_t : ISerializable
{
    crypto_clsag_signature_t() {}

    crypto_clsag_signature_t(
        std::vector<crypto_scalar_t> scalars,
        const crypto_scalar_t &challenge,
        const crypto_key_image_t &commitment_image = Crypto::Z,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z):
        scalars(std::move(scalars)),
        challenge(challenge),
        commitment_image(commitment_image),
        pseudo_commitment(pseudo_commitment)
    {
    }

    JSON_OBJECT_CONSTRUCTORS(crypto_clsag_signature_t, fromJSON)

    crypto_clsag_signature_t(const std::string &input)
    {
        const auto string = Crypto::StringTools::from_hex(input);

        deserializer_t reader(string);

        deserialize(reader);
    }

    crypto_clsag_signature_t(std::initializer_list<uint8_t> input)
    {
        std::vector<uint8_t> data(input);

        deserializer_t reader(data);

        deserialize(reader);
    }

    crypto_clsag_signature_t(const std::vector<uint8_t> &input)
    {
        deserializer_t reader(input);

        deserialize(reader);
    }

    crypto_clsag_signature_t(deserializer_t &reader)
    {
        deserialize(reader);
    }

    /**
     * Checks that the basic construction of the proof is valid
     * @param ring_size
     * @return
     */
    [[nodiscard]] bool check_construction(size_t ring_size, bool use_commitments = false) const
    {
        if (scalars.size() != ring_size)
        {
            return false;
        }

        if (!challenge.valid())
        {
            return false;
        }

        for (const auto &scalar : scalars)
        {
            if (!scalar.valid())
            {
                return false;
            }
        }

        if (use_commitments && !commitment_image.check_subgroup())
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
        scalars = reader.keyV<crypto_scalar_t>();

        challenge = reader.key<crypto_scalar_t>();

        if (reader.boolean())
        {
            commitment_image = reader.key<crypto_key_image_t>();

            pseudo_commitment = reader.key<crypto_pedersen_commitment_t>();
        }
    }

    JSON_FROM_FUNC(fromJSON) override
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEYV_FROM_JSON(scalars)

        LOAD_KEY_FROM_JSON(challenge)

        JSON_IF_MEMBER(commitment_image)
        LOAD_KEY_FROM_JSON(commitment_image)

        JSON_IF_MEMBER(pseudo_commitment)
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
     * @param writer
     */
    void serialize(serializer_t &writer) const override
    {
        writer.key(scalars);

        writer.key(challenge);

        if (commitment_image.valid())
        {
            writer.boolean(true);

            writer.key(commitment_image);

            writer.key(pseudo_commitment);
        }
        else
        {
            writer.boolean(false);
        }
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
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override
    {
        writer.StartObject();
        {
            KEYV_TO_JSON(scalars);

            KEY_TO_JSON(challenge);

            if (commitment_image.valid())
            {
                KEY_TO_JSON(commitment_image);

                KEY_TO_JSON(pseudo_commitment);
            }
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

    std::vector<crypto_scalar_t> scalars;
    crypto_key_image_t commitment_image;
    crypto_scalar_t challenge;
    crypto_pedersen_commitment_t pseudo_commitment;
};

namespace Crypto::RingSignature::CLSAG
{
    /**
     * Checks the CLSAG ring signature presented
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     * @param commitments
     * @param pseudo_commitment
     * @return
     */
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_clsag_signature_t &signature,
        const std::vector<crypto_pedersen_commitment_t> &commitments = {});

    /**
     * Completes the prepared CLSAG ring signature
     * @param signing_scalar
     * @param real_output_index
     * @param signature
     * @param h
     * @param mu_P
     * @param partial_signing_scalars
     * @return
     */
    std::tuple<bool, crypto_clsag_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        size_t real_output_index,
        const crypto_clsag_signature_t &signature,
        const std::vector<crypto_scalar_t> &h,
        const crypto_scalar_t &mu_P,
        const std::vector<crypto_scalar_t> &partial_signing_scalars = {});

    /**
     * Generates a partial signing scalar that is a factor of a full signing scalar and typically
     * used by multisig wallets -- input data is supplied from prepare_ring_signature
     * @param mu_P
     * @param spend_secret_key
     * @return
     */
    crypto_scalar_t
        generate_partial_signing_scalar(const crypto_scalar_t &mu_P, const crypto_secret_key_t &spend_secret_key);

    /**
     * Generates a CLSAG ring signature using the secrets provided
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     * @return
     */
    std::tuple<bool, crypto_clsag_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_secret_key_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_blinding_factor_t &input_blinding_factor = Crypto::ZERO,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments = {},
        const crypto_blinding_factor_t &pseudo_blinding_factor = Crypto::ZERO,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z);

    /**
     * Prepares a CLSAG ring signature using the primitive values provided
     * Must be completed via complete_ring_signature before it will validate
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     * @return
     */
    std::tuple<bool, crypto_clsag_signature_t, std::vector<crypto_scalar_t>, crypto_scalar_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index = 0,
        const crypto_blinding_factor_t &input_blinding_factor = Crypto::ZERO,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments = {},
        const crypto_blinding_factor_t &pseudo_blinding_factor = Crypto::ZERO,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z);
} // namespace Crypto::RingSignature::CLSAG

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_clsag_signature_t &value)
    {
        os << "CLSAG [" << value.size() << " bytes]:" << std::endl << "\tscalars:" << std::endl;

        for (const auto &val : value.scalars)
        {
            os << "\t\t" << val << std::endl;
        }

        os << "\tchallenge: " << value.challenge << std::endl;

        if (value.commitment_image.valid())
        {
            os << "\tcommitment_image: " << value.commitment_image << std::endl
               << "\tpseudo_commitment: " << value.pseudo_commitment << std::endl;
        }

        return os;
    }
} // namespace std

#endif // CRYPTO_RING_SIGNATURE_CLSAG_H
