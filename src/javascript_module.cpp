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

#include "crypto.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
using namespace emscripten;
#else
#error "Requires EMSCRIPTEN for compilation"
#endif

// These are provided here just to silence IDE warnings
#ifndef __EMSCRIPTEN__
#define EMSCRIPTEN_BINDINGS(a) void a()
#define function(a, b) const auto b = a;
#endif

#define INIT_RESULT()                                          \
    rapidjson::StringBuffer buffer;                            \
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer); \
    writer.StartArray();

#define END_RESULT()                        \
    writer.EndArray();                      \
    const auto output = buffer.GetString(); \
    return output;

#define EMS_METHOD(name) std::string name(const std::string &json)
#define EMS_EXPORT(func) function(#func, &func)
#define TO_KEY(value) const auto key = std::to_string(value)

static inline rapidjson::Document parse(const std::string &json)
{
    rapidjson::Document body;

    if (body.Parse(json.c_str()).HasParseError())
    {
        throw std::invalid_argument("Could not parse JSON");
    }

    return body;
}

#define PARSE_JSON() const auto info = parse(json)

static inline std::string
    prepare(bool success, const std::string &value1 = std::string(), const std::string &value2 = std::string())
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        if (!value1.empty())
        {
            writer.String(value1);
        }

        if (!value2.empty())
        {
            writer.String(value2);
        }
    }
    END_RESULT()
}

template<typename T>
static inline std::string prepare(bool success, const std::string &value1, const std::vector<T> &values2)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.String(value1);

        writer.StartArray();
        {
            for (const auto &value : values2)
            {
                writer.String(value.to_string());
            }
        }
        writer.EndArray();
    }
    END_RESULT()
}

static inline std::string
    prepare(bool success, const std::string &value1, const std::vector<std::string> &values2, const std::string &value3)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.String(value1);

        writer.StartArray();
        {
            for (const auto &value : values2)
            {
                writer.String(value);
            }
        }
        writer.EndArray();

        writer.String(value3);
    }
    END_RESULT()
}

template<typename T>
static inline std::string prepare(
    bool success,
    const std::string &value1,
    const std::vector<std::vector<T>> &values2,
    const std::string &value3)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.String(value1);

        writer.StartArray();
        {
            for (const auto &level1 : values2)
            {
                writer.StartArray();
                {
                    for (const auto &value : level1)
                    {
                        writer.String(value.to_string());
                    }
                }
                writer.EndArray();
            }
        }
        writer.EndArray();

        writer.String(value3);
    }
    END_RESULT()
}

template<typename T>
static inline std::string
    prepare(bool success, const std::string &value1, const std::vector<T> &values2, const std::string &value3)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.String(value1);

        writer.StartArray();
        {
            for (const auto &value : values2)
            {
                writer.String(value.to_string());
            }
        }
        writer.EndArray();

        writer.String(value3);
    }
    END_RESULT()
}

static inline std::string prepare(bool success, const uint32_t value)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.Uint(value);
    }
    END_RESULT()
}

static inline std::string prepare(bool success, const std::vector<std::string> &values1)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.StartArray();
        {
            for (const auto &value : values1)
            {
                writer.String(value);
            }
        }
        writer.EndArray();
    }
    END_RESULT()
}

template<typename T> static inline std::string prepare(bool success, const std::vector<T> &values1)
{
    INIT_RESULT()
    {
        writer.Bool(!success);

        writer.StartArray();
        {
            for (const auto &value : values1)
            {
                writer.String(value.to_string());
            }
        }
        writer.EndArray();
    }
    END_RESULT()
}

template<typename T, typename U>
static inline std::string prepare(bool success, const std::vector<T> &values1, const std::vector<U> &values2)
{
    INIT_RESULT()
    {
        writer.Bool(!success);


        writer.StartArray();
        {
            for (const auto &value : values1)
            {
                writer.String(value.to_string());
            }
        }
        writer.EndArray();


        writer.StartArray();
        {
            for (const auto &value : values2)
            {
                writer.String(value.to_string());
            }
        }
        writer.EndArray();
    }
    END_RESULT()
}

static inline std::string error(const std::exception &exception)
{
    return prepare(false, exception.what());
}

template<typename T> static inline T get(const rapidjson::Document &document, uint8_t index)
{
    T result = T();

    TO_KEY(index);

    return result;
}

template<> inline std::string get<std::string>(const rapidjson::Document &document, uint8_t index)
{
    auto result = std::string();

    TO_KEY(index);

    if (has_member(document, key))
    {
        const auto &val = get_json_value(document, key);

        if (val.IsString())
        {
            result = get_json_string(val);
        }
    }

    return result;
}

template<> inline uint32_t get<uint32_t>(const rapidjson::Document &document, uint8_t index)
{
    uint32_t result = 0;

    TO_KEY(index);

    if (has_member(document, key))
    {
        const auto &val = get_json_value(document, key);

        if (val.IsUint())
        {
            result = get_json_uint32_t(val);
        }
    }

    return result;
}

template<> inline uint64_t get<uint64_t>(const rapidjson::Document &document, uint8_t index)
{
    uint64_t result = 0;

    TO_KEY(index);

    if (has_member(document, key))
    {
        const auto &val = get_json_value(document, key);

        if (val.IsUint())
        {
            result = get_json_uint64_t(val);
        }
    }

    return result;
}

template<typename T> static inline T get_crypto_t(const rapidjson::Document &document, uint8_t index)
{
    T result;

    const auto value = get<std::string>(document, index);

    if (!value.empty())
    {
        result = value;
    }

    return result;
}

template<typename T> static inline std::vector<T> get_vector(const rapidjson::Value &value)
{
    std::vector<T> results;

    try
    {
        if (value.IsArray())
        {
            for (const auto &element : get_json_array(value))
            {
                if (element.IsString())
                {
                    results.push_back(get_json_string(element));
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        PRINTF(e.what());

        results.clear();
    }

    return results;
}

template<typename T> static inline std::vector<T> get_vector(const rapidjson::Document &document, uint8_t index)
{
    std::vector<T> results;

    const auto key = std::to_string(index);

    if (has_member(document, key))
    {
        const auto &val = get_json_value(document, key);

        results = get_vector<T>(val);
    }

    return results;
}

static inline std::vector<uint64_t> get_uint64_t_vector(const rapidjson::Document &document, uint8_t index)
{
    std::vector<uint64_t> results;

    try
    {
        const auto key = std::to_string(index);

        if (has_member(document, key))
        {
            const auto &val = get_json_value(document, key);

            if (val.IsArray())
            {
                for (const auto &value : get_json_array(val))
                {
                    if (value.IsUint64())
                    {
                        results.push_back(get_json_uint64_t(value));
                    }
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        PRINTF(e.what());

        results.clear();
    }

    return results;
}

template<typename T>
static inline std::vector<std::vector<T>> get_vector_vector(const rapidjson::Document &document, uint8_t index)
{
    std::vector<std::vector<T>> results;

    const auto key = std::to_string(index);

    if (has_member(document, key))
    {
        const auto &outer_array = get_json_value(document, key);

        if (outer_array.IsArray())
        {
            const auto outer_elements = get_json_array(outer_array);

            for (const auto &inner_array : outer_elements)
            {
                if (inner_array.IsArray())
                {
                    const auto inner_elements = get_vector<T>(inner_array);

                    if (!inner_elements.empty())
                    {
                        results.push_back(inner_elements);
                    }
                }
            }
        }
    }

    return results;
}

/**
 * Mapped methods from base58.cpp
 */

EMS_METHOD(base58_encode)
{
    try
    {
        PARSE_JSON();

        const auto hex = get<std::string>(info, 0);

        if (!hex.empty())
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::Base58::encode(reader);

            return prepare(true, base58);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(base58_encode_check)
{
    try
    {
        PARSE_JSON();

        const auto hex = get<std::string>(info, 0);

        if (!hex.empty())
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::Base58::encode_check(reader);

            return prepare(true, base58);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(base58_decode)
{
    try
    {
        PARSE_JSON();

        const auto base58 = get<std::string>(info, 0);

        if (!base58.empty())
        {
            const auto [success, decoded] = Crypto::Base58::decode(base58);

            if (success)
            {
                return prepare(true, decoded.to_string());
            }

            return prepare(false, "");
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(base58_decode_check)
{
    try
    {
        PARSE_JSON();

        const auto base58 = get<std::string>(info, 0);

        if (!base58.empty())
        {
            const auto [success, decoded] = Crypto::Base58::decode_check(base58);

            if (success)
            {
                return prepare(true, decoded.to_string());
            }

            return prepare(false, "");
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from cn_base58.cpp
 */

EMS_METHOD(cn_base58_encode)
{
    try
    {
        PARSE_JSON();

        const auto hex = get<std::string>(info, 0);

        if (!hex.empty())
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::CNBase58::encode(reader);

            return prepare(true, base58);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(cn_base58_encode_check)
{
    try
    {
        PARSE_JSON();

        const auto hex = get<std::string>(info, 0);

        if (!hex.empty())
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::CNBase58::encode_check(reader);

            return prepare(true, base58);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(cn_base58_decode)
{
    try
    {
        PARSE_JSON();

        const auto base58 = get<std::string>(info, 0);

        if (!base58.empty())
        {
            const auto [success, decoded] = Crypto::CNBase58::decode(base58);

            if (success)
            {
                return prepare(true, decoded.to_string());
            }

            return prepare(false, "");
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(cn_base58_decode_check)
{
    try
    {
        PARSE_JSON();

        const auto base58 = get<std::string>(info, 0);

        if (!base58.empty())
        {
            const auto [success, decoded] = Crypto::CNBase58::decode_check(base58);

            if (success)
            {
                return prepare(true, decoded.to_string());
            }

            return prepare(false, "");
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from bulletproofs.cpp
 */

EMS_METHOD(bulletproofs_prove)
{
    try
    {
        PARSE_JSON();

        const auto amounts = get_uint64_t_vector(info, 0);

        const auto blinding_factors = get_vector<crypto_blinding_factor_t>(info, 1);

        auto N = get<uint32_t>(info, 2);

        if (N == 0)
        {
            N = 64;
        }

        if (!amounts.empty() && !blinding_factors.empty())
        {
            const auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove(amounts, blinding_factors, N);

            JSON_INIT();

            proof.toJSON(writer);

            JSON_DUMP(proof_json);

            return prepare(true, proof_json, commitments);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(bulletproofs_verify)
{
    try
    {
        PARSE_JSON();

        const auto proofs_array = get<std::string>(info, 0);

        const auto commitments = get_vector_vector<crypto_pedersen_commitment_t>(info, 1);

        auto N = get<uint32_t>(info, 2);

        if (N == 0)
        {
            N = 64;
        }

        if (!proofs_array.empty() && !commitments.empty())
        {
            std::vector<crypto_bulletproof_t> proofs;

            JSON_PARSE(proofs_array);

            for (const auto &elem : get_json_array(body))
            {
                const auto proof = crypto_bulletproof_t(elem);

                proofs.push_back(proof);
            }

            const auto success = Crypto::RangeProofs::Bulletproofs::verify(proofs, commitments, N);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from bulletproofsplus.cpp
 */

EMS_METHOD(bulletproofsplus_prove)
{
    try
    {
        PARSE_JSON();

        const auto amounts = get_uint64_t_vector(info, 0);

        const auto blinding_factors = get_vector<crypto_blinding_factor_t>(info, 1);

        auto N = get<uint32_t>(info, 2);

        if (N == 0)
        {
            N = 64;
        }

        if (!amounts.empty() && !blinding_factors.empty())
        {
            const auto [proof, commitments] =
                Crypto::RangeProofs::BulletproofsPlus::prove(amounts, blinding_factors, N);

            JSON_INIT();

            proof.toJSON(writer);

            JSON_DUMP(proof_json);

            return prepare(true, proof_json, commitments);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(bulletproofsplus_verify)
{
    try
    {
        PARSE_JSON();

        const auto proofs_array = get<std::string>(info, 0);

        const auto commitments = get_vector_vector<crypto_pedersen_commitment_t>(info, 1);

        auto N = get<uint32_t>(info, 2);

        if (N == 0)
        {
            N = 64;
        }

        if (!proofs_array.empty() && !commitments.empty())
        {
            std::vector<crypto_bulletproof_plus_t> proofs;

            JSON_PARSE(proofs_array);

            for (const auto &elem : get_json_array(body))
            {
                const auto proof = crypto_bulletproof_plus_t(elem);

                proofs.push_back(proof);
            }

            const auto success = Crypto::RangeProofs::BulletproofsPlus::verify(proofs, commitments, N);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from crypto_common.cpp
 */

EMS_METHOD(calculate_base2_exponent)
{
    try
    {
        PARSE_JSON();

        const auto value = get<uint32_t>(info, 0);

        const auto [success, exponent] = Crypto::calculate_base2_exponent(value);

        return prepare(success, exponent);
    }
    catch (const std::exception e)
    {
        return error(e);
    }
}

EMS_METHOD(check_point)
{
    try
    {
        PARSE_JSON();

        const auto point = get<std::string>(info, 0);

        if (!point.empty())
        {
            const auto success = Crypto::check_point(point);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(check_scalar)
{
    try
    {
        PARSE_JSON();

        const auto scalar = get<std::string>(info, 0);

        if (!scalar.empty())
        {
            const auto success = Crypto::check_scalar(scalar);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(derivation_to_scalar)
{
    try
    {
        PARSE_JSON();

        const auto derivation = get<std::string>(info, 0);

        const auto output_index = get<uint64_t>(info, 1);

        if (!derivation.empty())
        {
            const auto scalar = Crypto::derivation_to_scalar(derivation, output_index);

            return prepare(true, scalar.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(derive_public_key)
{
    try
    {
        PARSE_JSON();

        const auto derivation = get<std::string>(info, 0);

        const auto public_key = get<std::string>(info, 1);

        if (!derivation.empty() && !public_key.empty())
        {
            const auto key = Crypto::derive_public_key(derivation, public_key);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(derive_secret_key)
{
    try
    {
        PARSE_JSON();

        const auto derivation = get<std::string>(info, 0);

        const auto secret_key = get<std::string>(info, 1);

        if (!derivation.empty() && !secret_key.empty())
        {
            const auto key = Crypto::derive_secret_key(derivation, secret_key);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_key_derivation)
{
    try
    {
        PARSE_JSON();

        const auto public_key = get<std::string>(info, 0);

        const auto secret_key = get<std::string>(info, 1);

        if (!public_key.empty() && !secret_key.empty())
        {
            const auto key = Crypto::generate_key_derivation(public_key, secret_key);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_key_image)
{
    try
    {
        PARSE_JSON();

        const auto public_key = get<std::string>(info, 0);

        const auto secret_key = get<std::string>(info, 1);

        const auto partial_key_images = get_vector<crypto_key_image_t>(info, 2);

        if (!public_key.empty() && !secret_key.empty())
        {
            const auto key = Crypto::generate_key_image(public_key, secret_key, partial_key_images);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_key_image_v2)
{
    try
    {
        PARSE_JSON();

        const auto secret_key = get<std::string>(info, 0);

        if (!secret_key.empty())
        {
            const auto key = Crypto::generate_key_image_v2(secret_key);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_keys)
{
    try
    {
        const auto [public_key, secret_key] = Crypto::generate_keys();

        return prepare(true, public_key.to_string(), secret_key.to_string());
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_wallet_seed)
{
    try
    {
        PARSE_JSON();

        const auto entropy = get<std::string>(info, 0);

        deserializer_t reader(entropy);

        const auto [seed, words, timestamp] = Crypto::generate_wallet_seed(reader.unread_data());

        serializer_t writer;

        writer.uint64(timestamp);

        return prepare(true, seed.to_string(), words, writer.to_string());
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_wallet_spend_keys)
{
    try
    {
        PARSE_JSON();

        const auto wallet_seed = get<std::string>(info, 0);

        const auto subwallet_index = get<uint64_t>(info, 1);

        if (!wallet_seed.empty())
        {
            const auto [public_key, secret_key] = Crypto::generate_wallet_spend_keys(wallet_seed, subwallet_index);

            return prepare(true, public_key.to_string(), secret_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_wallet_view_keys)
{
    try
    {
        PARSE_JSON();

        const auto wallet_seed = get<std::string>(info, 0);

        if (!wallet_seed.empty())
        {
            const auto [public_key, secret_key] = Crypto::generate_wallet_view_keys(wallet_seed);

            return prepare(true, public_key.to_string(), secret_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(hash_to_point)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::hash_to_point(input.data(), input.size());

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(hash_to_scalar)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::hash_to_scalar(input.data(), input.size());

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(pow2_round)
{
    try
    {
        PARSE_JSON();

        const auto input = get<uint32_t>(info, 0);

        const auto result = Crypto::pow2_round(input);

        return prepare(true, result);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(random_hash)
{
    try
    {
        const auto result = Crypto::random_hash();

        return prepare(true, result.to_string());
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(random_hashes)
{
    try
    {
        PARSE_JSON();

        const auto count = get<uint32_t>(info, 0);

        const auto results = Crypto::random_hashes(count);

        return prepare(true, results);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(random_point)
{
    try
    {
        const auto result = Crypto::random_point();

        return prepare(true, result.to_string());
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(random_points)
{
    try
    {
        PARSE_JSON();

        const auto count = get<uint32_t>(info, 0);

        const auto results = Crypto::random_points(count);

        return prepare(true, results);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(random_scalar)
{
    try
    {
        const auto result = Crypto::random_scalar();

        return prepare(true, result.to_string());
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(random_scalars)
{
    try
    {
        PARSE_JSON();

        const auto count = get<uint32_t>(info, 0);

        const auto results = Crypto::random_scalars(count);

        return prepare(true, results);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(restore_wallet_seed)
{
    try
    {
        PARSE_JSON();

        const auto words = get_vector<std::string>(info, 0);

        if (!words.empty())
        {
            const auto [decode_success, decoded, timestamp] = Crypto::Mnemonics::decode(words);

            if (decode_success)
            {
                serializer_t writer;

                writer.uint64(timestamp);

                return prepare(true, decoded.to_string(), writer.to_string());
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(secret_key_to_public_key)
{
    try
    {
        PARSE_JSON();

        const auto secret_key = get<std::string>(info, 0);

        if (!secret_key.empty())
        {
            const auto public_key = Crypto::secret_key_to_public_key(secret_key);

            return prepare(true, public_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(underive_public_key)
{
    try
    {
        PARSE_JSON();

        const auto derivation = get<std::string>(info, 0);

        const auto output_index = get<uint64_t>(info, 1);

        const auto public_ephemeral = get<std::string>(info, 2);

        if (!derivation.empty() && !public_ephemeral.empty())
        {
            const auto public_key = Crypto::underive_public_key(derivation, output_index, public_ephemeral);

            return prepare(true, public_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from hashing.cpp
 */

EMS_METHOD(argon2d)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        const auto iterations = get<uint32_t>(info, 1);

        const auto memory = get<uint32_t>(info, 2);

        const auto threads = get<uint32_t>(info, 3);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::Hashing::argon2d(
                input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(argon2i)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        const auto iterations = get<uint32_t>(info, 1);

        const auto memory = get<uint32_t>(info, 2);

        const auto threads = get<uint32_t>(info, 3);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::Hashing::argon2i(
                input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(argon2id)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        const auto iterations = get<uint32_t>(info, 1);

        const auto memory = get<uint32_t>(info, 2);

        const auto threads = get<uint32_t>(info, 3);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::Hashing::argon2id(
                input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(sha3)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::Hashing::sha3(input.data(), input.size());

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(sha3_slow_hash)
{
    try
    {
        PARSE_JSON();

        const auto data = get<std::string>(info, 0);

        const auto iterations = get<uint32_t>(info, 1);

        if (!data.empty())
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto result = Crypto::Hashing::sha3_slow_hash(input.data(), input.size(), iterations);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(tree_branch)
{
    try
    {
        PARSE_JSON();

        const auto hashes = get_vector<crypto_hash_t>(info, 0);

        if (!hashes.empty())
        {
            const auto tree_branches = Crypto::Hashing::Merkle::tree_branch(hashes);

            return prepare(true, tree_branches);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(tree_depth)
{
    try
    {
        PARSE_JSON();

        const auto count = get<uint32_t>(info, 0);

        const auto depth = uint32_t(Crypto::Hashing::Merkle::tree_depth(count));

        return prepare(true, depth);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(root_hash)
{
    try
    {
        PARSE_JSON();

        const auto hashes = get_vector<crypto_hash_t>(info, 0);

        if (!hashes.empty())
        {
            const auto root_hash = Crypto::Hashing::Merkle::root_hash(hashes);

            return prepare(true, root_hash.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(root_hash_from_branch)
{
    try
    {
        PARSE_JSON();

        const auto hashes = get_vector<crypto_hash_t>(info, 0);

        const auto depth = get<uint32_t>(info, 1);

        const auto leaf = get<std::string>(info, 2);

        const auto path = get<uint8_t>(info, 3);

        if (!hashes.empty() && !leaf.empty() && path <= 1)
        {
            const auto root_hash = Crypto::Hashing::Merkle::root_hash_from_branch(hashes, depth, leaf, path);

            return prepare(true, root_hash.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from mnemonics.cpp
 */

EMS_METHOD(mnemonics_calculate_checksum_index)
{
    try
    {
        PARSE_JSON();

        const auto words = get_vector<std::string>(info, 0);

        if (!words.empty())
        {
            const auto index = uint32_t(Crypto::Mnemonics::calculate_checksum_index(words));

            if (index >= 0)
            {
                return prepare(true, index);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(mnemonics_decode)
{
    try
    {
        PARSE_JSON();

        const auto words = get_vector<std::string>(info, 0);

        if (!words.empty())
        {
            const auto [decode_success, decoded, timestamp] = Crypto::Mnemonics::decode(words);

            if (decode_success)
            {
                serializer_t writer;

                writer.uint64(timestamp);

                return prepare(true, decoded.to_string(), writer.to_string());
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(mnemonics_encode)
{
    try
    {
        PARSE_JSON();

        const auto seed = get<std::string>(info, 0);

        const auto timestamp_str = get<std::string>(info, 1);

        const auto auto_timestamp = (get<uint64_t>(info, 2) == 1);

        if (!seed.empty())
        {
            deserializer_t reader(timestamp_str);

            const auto timestamp = reader.uint64();

            const auto words = Crypto::Mnemonics::encode(seed, timestamp, auto_timestamp);

            return prepare(true, words);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(mnemonics_word_index)
{
    try
    {
        PARSE_JSON();

        const auto word = get<std::string>(info, 0);

        if (!word.empty())
        {
            const auto index = uint32_t(Crypto::Mnemonics::word_index(word));

            if (index != -1)
            {
                return prepare(true, index);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(mnemonics_word_list)
{
    try
    {
        PARSE_JSON();

        const auto words = Crypto::Mnemonics::word_list();

        return prepare(true, words);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(mnemonics_word_list_trimmed)
{
    try
    {
        PARSE_JSON();

        const auto words = Crypto::Mnemonics::word_list_trimmed();

        return prepare(true, words);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from multisig.cpp
 */

EMS_METHOD(generate_multisig_secret_key)
{
    try
    {
        PARSE_JSON();

        const auto their_public_key = get<std::string>(info, 0);

        const auto our_secret_key = get<std::string>(info, 1);

        if (!their_public_key.empty() && !our_secret_key.empty())
        {
            const auto secret_key = Crypto::Multisig::generate_multisig_secret_key(their_public_key, our_secret_key);

            return prepare(true, secret_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_multisig_secret_keys)
{
    try
    {
        PARSE_JSON();

        const auto their_public_keys = get_vector<crypto_public_key_t>(info, 0);

        const auto our_secret_key = get<std::string>(info, 1);

        if (!their_public_keys.empty() && !our_secret_key.empty())
        {
            const auto secret_keys = Crypto::Multisig::generate_multisig_secret_keys(their_public_keys, our_secret_key);

            return prepare(true, secret_keys);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_shared_public_key)
{
    try
    {
        PARSE_JSON();

        const auto keys = get_vector<crypto_public_key_t>(info, 0);

        if (!keys.empty())
        {
            const auto key = Crypto::Multisig::generate_shared_public_key(keys);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_shared_secret_key)
{
    try
    {
        PARSE_JSON();

        const auto keys = get_vector<crypto_secret_key_t>(info, 0);

        if (!keys.empty())
        {
            const auto key = Crypto::Multisig::generate_shared_secret_key(keys);

            return prepare(true, key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(rounds_required)
{
    try
    {
        PARSE_JSON();

        const auto participants = get<uint32_t>(info, 0);

        const auto threshold = get<uint32_t>(info, 1);

        const auto rounds = uint32_t(Crypto::Multisig::rounds_required(participants, threshold));

        return prepare(true, rounds);
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from ringct.cpp
 */

EMS_METHOD(check_commitments_parity)
{
    try
    {
        PARSE_JSON();

        const auto pseudo_commitments = get_vector<crypto_pedersen_commitment_t>(info, 0);

        const auto output_commitments = get_vector<crypto_pedersen_commitment_t>(info, 1);

        const auto transaction_fee = get<uint64_t>(info, 2);

        if (!pseudo_commitments.empty() && !output_commitments.empty())
        {
            const auto success =
                Crypto::RingCT::check_commitments_parity(pseudo_commitments, output_commitments, transaction_fee);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_amount_mask)
{
    try
    {
        PARSE_JSON();

        const auto derivation_scalar = get<std::string>(info, 0);

        if (!derivation_scalar.empty())
        {
            const auto result = Crypto::RingCT::generate_amount_mask(derivation_scalar);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_commitment_blinding_factor)
{
    try
    {
        PARSE_JSON();

        const auto derivation_scalar = get<std::string>(info, 0);

        if (!derivation_scalar.empty())
        {
            const auto result = Crypto::RingCT::generate_commitment_blinding_factor(derivation_scalar);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_pedersen_commitment)
{
    try
    {
        PARSE_JSON();

        const auto blinding_factor = get<std::string>(info, 0);

        const auto amount = get<uint64_t>(info, 1);

        if (!blinding_factor.empty())
        {
            const auto result = Crypto::RingCT::generate_pedersen_commitment(blinding_factor, amount);

            return prepare(true, result.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_pseudo_commitments)
{
    try
    {
        PARSE_JSON();

        const auto input_amounts = get_uint64_t_vector(info, 0);

        const auto output_blinding_factors = get_vector<crypto_blinding_factor_t>(info, 1);

        if (!input_amounts.empty() && !output_blinding_factors.empty())
        {
            const auto [blinding_factors, commitments] =
                Crypto::RingCT::generate_pseudo_commitments(input_amounts, output_blinding_factors);

            return prepare(true, blinding_factors, commitments);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(toggle_masked_amount)
{
    try
    {
        PARSE_JSON();

        const auto amount_mask = get<std::string>(info, 0);

        const auto amount_hex = get<std::string>(info, 1);

        const auto amount = get<uint64_t>(info, 1);

        if (!amount_mask.empty())
        {
            if (!amount_hex.empty())
            {
                const auto amount_bytes = Crypto::StringTools::from_hex(amount_hex);

                const auto masked_amount =
                    Crypto::RingCT::toggle_masked_amount(amount_mask, amount_bytes).to_uint64_t();

                const auto result = Crypto::StringTools::to_hex(&masked_amount, sizeof(uint64_t));

                return prepare(true, result);
            }
            else
            {
                const auto masked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, amount).to_uint64_t();

                const auto result = Crypto::StringTools::to_hex(&masked_amount, sizeof(uint64_t));

                return prepare(true, result);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from ring_signature_borromean.cpp
 */

EMS_METHOD(borromean_check_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto key_image = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto signature_obj = get<std::string>(info, 3);

        if (!message_digest.empty() && !key_image.empty() && !public_keys.empty() && !signature_obj.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_borromean_signature_t(body);

            const auto success = Crypto::RingSignature::Borromean::check_ring_signature(
                message_digest, key_image, public_keys, signature);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(borromean_complete_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto signing_scalar = get<std::string>(info, 0);

        const auto real_output_index = get<uint32_t>(info, 1);

        const auto signature_obj = get<std::string>(info, 2);

        const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 3);

        if (!signing_scalar.empty() && !signing_scalar.empty() && !signature_obj.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_borromean_signature_t(body);

            const auto [success, sig] = Crypto::RingSignature::Borromean::complete_ring_signature(
                signing_scalar, real_output_index, signature, partial_signing_scalars);

            if (success)
            {
                JSON_INIT();

                sig.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(borromean_generate_partial_signing_scalar)
{
    try
    {
        PARSE_JSON();

        const auto real_output_index = get<uint32_t>(info, 0);

        const auto signature_obj = get<std::string>(info, 1);

        const auto spend_secret_key = get<std::string>(info, 2);

        if (!signature_obj.empty() && !spend_secret_key.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_borromean_signature_t(body);

            const auto partial_signing_scalar = Crypto::RingSignature::Borromean::generate_partial_signing_scalar(
                real_output_index, signature, spend_secret_key);

            return prepare(true, partial_signing_scalar.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(borromean_generate_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto secret_ephemeral = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        if (!message_digest.empty() && !secret_ephemeral.empty() && !public_keys.empty())
        {
            const auto [success, signature] = Crypto::RingSignature::Borromean::generate_ring_signature(
                message_digest, secret_ephemeral, public_keys);

            if (success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(borromean_prepare_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto key_image = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto real_output_index = get<uint32_t>(info, 3);

        if (!message_digest.empty() && !key_image.empty() && !public_keys.empty())
        {
            const auto [success, signature] = Crypto::RingSignature::Borromean::prepare_ring_signature(
                message_digest, key_image, public_keys, real_output_index);

            if (success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from ring_signature_clsag.cpp
 */

EMS_METHOD(clsag_check_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto key_image = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto signature_obj = get<std::string>(info, 3);

        const auto commitments = get_vector<crypto_pedersen_commitment_t>(info, 4);

        if (!message_digest.empty() && !key_image.empty() && !public_keys.empty() && !signature_obj.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_clsag_signature_t(body);

            const auto success = Crypto::RingSignature::CLSAG::check_ring_signature(
                message_digest, key_image, public_keys, signature, commitments);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(clsag_complete_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto signing_scalar = get<std::string>(info, 0);

        const auto real_output_index = get<uint32_t>(info, 1);

        const auto signature_obj = get<std::string>(info, 2);

        const auto h = get_vector<crypto_scalar_t>(info, 3);

        const auto mu_P = get<std::string>(info, 4);

        const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 5);

        if (!signing_scalar.empty() && !h.empty() && !mu_P.empty() && !signature_obj.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_clsag_signature_t(body);

            const auto [success, sig] = Crypto::RingSignature::CLSAG::complete_ring_signature(
                signing_scalar, real_output_index, signature, h, mu_P, partial_signing_scalars);

            if (success)
            {
                JSON_INIT();

                sig.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(clsag_generate_partial_signing_scalar)
{
    try
    {
        PARSE_JSON();

        const auto mu_P = get<std::string>(info, 0);

        const auto spend_secret_key = get<std::string>(info, 1);

        if (!mu_P.empty() && !spend_secret_key.empty())
        {
            const auto partial_signing_key =
                Crypto::RingSignature::CLSAG::generate_partial_signing_scalar(mu_P, spend_secret_key);

            return prepare(true, partial_signing_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(clsag_generate_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto secret_ephemeral = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto input_blinding_factor = get_crypto_t<crypto_blinding_factor_t>(info, 3);

        const auto public_commitments = get_vector<crypto_pedersen_commitment_t>(info, 4);

        const auto pseudo_blinding_factor = get_crypto_t<crypto_blinding_factor_t>(info, 5);

        const auto pseudo_commitment = get_crypto_t<crypto_pedersen_commitment_t>(info, 6);

        if (!message_digest.empty() && !secret_ephemeral.empty() && !public_keys.empty())
        {
            const auto [success, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
                message_digest,
                secret_ephemeral,
                public_keys,
                input_blinding_factor,
                public_commitments,
                pseudo_blinding_factor,
                pseudo_commitment);

            if (success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(clsag_prepare_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto key_image = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto real_output_index = get<uint32_t>(info, 3);

        const auto input_blinding_factor = get_crypto_t<crypto_blinding_factor_t>(info, 4);

        const auto public_commitments = get_vector<crypto_pedersen_commitment_t>(info, 5);

        const auto pseudo_blinding_factor = get_crypto_t<crypto_blinding_factor_t>(info, 6);

        const auto pseudo_commitment = get_crypto_t<crypto_pedersen_commitment_t>(info, 7);

        if (!message_digest.empty() && !key_image.empty() && !public_keys.empty())
        {
            const auto [success, signature, h, mu_P] = Crypto::RingSignature::CLSAG::prepare_ring_signature(
                message_digest,
                key_image,
                public_keys,
                real_output_index,
                input_blinding_factor,
                public_commitments,
                pseudo_blinding_factor,
                pseudo_commitment);

            if (success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json, h, mu_P.to_string());
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from ring_signature_triptych.cpp
 */

EMS_METHOD(triptych_check_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto key_image = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto signature_obj = get<std::string>(info, 3);

        const auto commitments = get_vector<crypto_pedersen_commitment_t>(info, 4);

        if (!message_digest.empty() && !key_image.empty() && !public_keys.empty() && !signature_obj.empty()
            && !commitments.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_triptych_signature_t(body);

            const auto success = Crypto::RingSignature::Triptych::check_ring_signature(
                message_digest, key_image, public_keys, signature, commitments);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(triptych_complete_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto signing_scalar = get<std::string>(info, 0);

        const auto signature_obj = get<std::string>(info, 1);

        const auto xpow = get<std::string>(info, 2);

        const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 3);

        if (!signing_scalar.empty() && !signature_obj.empty() && !xpow.empty())
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_triptych_signature_t(body);

            const auto [success, sig] = Crypto::RingSignature::Triptych::complete_ring_signature(
                signing_scalar, signature, xpow, partial_signing_scalars);

            if (success)
            {
                JSON_INIT();

                sig.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(triptych_generate_partial_signing_scalar)
{
    try
    {
        PARSE_JSON();

        const auto spend_secret_key = get<std::string>(info, 0);

        const auto xpow = get<std::string>(info, 1);

        if (!spend_secret_key.empty() && !xpow.empty())
        {
            const auto partial_signing_key =
                Crypto::RingSignature::Triptych::generate_partial_signing_scalar(spend_secret_key, xpow);

            return prepare(true, partial_signing_key.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(triptych_generate_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto secret_ephemeral = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto input_blinding_factor = get<std::string>(info, 3);

        const auto public_commitments = get_vector<crypto_pedersen_commitment_t>(info, 4);

        const auto pseudo_blinding_factor = get<std::string>(info, 5);

        const auto pseudo_commitment = get<std::string>(info, 6);

        if (!message_digest.empty() && !secret_ephemeral.empty() && !public_keys.empty()
            && !input_blinding_factor.empty() && !public_commitments.empty() && !pseudo_blinding_factor.empty()
            && !pseudo_commitment.empty())
        {
            const auto [success, signature] = Crypto::RingSignature::Triptych::generate_ring_signature(
                message_digest,
                secret_ephemeral,
                public_keys,
                input_blinding_factor,
                public_commitments,
                pseudo_blinding_factor,
                pseudo_commitment);

            if (success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json);
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(triptych_prepare_ring_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto key_image = get<std::string>(info, 1);

        const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

        const auto real_output_index = get<uint32_t>(info, 3);

        const auto input_blinding_factor = get<std::string>(info, 4);

        const auto public_commitments = get_vector<crypto_pedersen_commitment_t>(info, 5);

        const auto pseudo_blinding_factor = get<std::string>(info, 6);

        const auto pseudo_commitment = get<std::string>(info, 7);

        if (!message_digest.empty() && !key_image.empty() && !public_keys.empty() && !input_blinding_factor.empty()
            && !public_commitments.empty() && !pseudo_blinding_factor.empty() && !pseudo_commitment.empty())
        {
            const auto [success, signature, xpow] = Crypto::RingSignature::Triptych::prepare_ring_signature(
                message_digest,
                key_image,
                public_keys,
                real_output_index,
                input_blinding_factor,
                public_commitments,
                pseudo_blinding_factor,
                pseudo_commitment);

            if (success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(sig_json);

                return prepare(success, sig_json, xpow.to_string());
            }
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

/**
 * Mapped methods from signature.cpp
 */

EMS_METHOD(check_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto public_key = get<std::string>(info, 1);

        const auto signature = get<std::string>(info, 2);

        if (!message_digest.empty() && !public_key.empty() && !signature.empty())
        {
            const auto success = Crypto::Signature::check_signature(message_digest, public_key, signature);

            return prepare(!success);
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(complete_signature)
{
    try
    {
        PARSE_JSON();

        const auto signing_scalar = get<std::string>(info, 0);

        const auto signature = get<std::string>(info, 1);

        const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 2);

        if (!signing_scalar.empty() && !signature.empty())
        {
            const auto sig = Crypto::Signature::complete_signature(signing_scalar, signature, partial_signing_scalars);

            return prepare(true, sig.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_partial_signing_scalar)
{
    try
    {
        PARSE_JSON();

        const auto signature = get<std::string>(info, 0);

        const auto spend_secret_key = get<std::string>(info, 1);

        if (!signature.empty() && !spend_secret_key.empty())
        {
            const auto partial_signing_scalar =
                Crypto::Signature::generate_partial_signing_scalar(signature, spend_secret_key);

            return prepare(true, partial_signing_scalar.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(generate_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto secret_key = get<std::string>(info, 1);

        if (!message_digest.empty() && !secret_key.empty())
        {
            const auto signature = Crypto::Signature::generate_signature(message_digest, secret_key);

            return prepare(true, signature.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMS_METHOD(prepare_signature)
{
    try
    {
        PARSE_JSON();

        const auto message_digest = get<std::string>(info, 0);

        const auto public_key = get<std::string>(info, 1);

        if (!message_digest.empty() && !public_key.empty())
        {
            const auto signature = Crypto::Signature::prepare_signature(message_digest, public_key);

            return prepare(true, signature.to_string());
        }

        return error(std::invalid_argument("invalid method argument"));
    }
    catch (const std::exception &e)
    {
        return error(e);
    }
}

EMSCRIPTEN_BINDINGS(InitModule)
{
    // Mapped methods from base58.cpp
    {
        EMS_EXPORT(base58_encode);

        EMS_EXPORT(base58_encode_check);

        EMS_EXPORT(base58_decode);

        EMS_EXPORT(base58_decode_check);
    }

    // Mapped methods from cn_base58.cpp
    {
        EMS_EXPORT(cn_base58_encode);

        EMS_EXPORT(cn_base58_encode_check);

        EMS_EXPORT(cn_base58_decode);

        EMS_EXPORT(cn_base58_decode_check);
    }

    // Mapped methods from bulletproofs.cpp
    {
        EMS_EXPORT(bulletproofs_prove);

        EMS_EXPORT(bulletproofs_verify);
    }

    // Mapped methods from bulletproofsplus.cpp
    {
        EMS_EXPORT(bulletproofsplus_prove);

        EMS_EXPORT(bulletproofsplus_verify);
    }

    // Mapped methods from crypto_common.cpp
    {
        EMS_EXPORT(calculate_base2_exponent);

        EMS_EXPORT(check_point);

        EMS_EXPORT(check_scalar);

        EMS_EXPORT(derivation_to_scalar);

        EMS_EXPORT(derive_public_key);

        EMS_EXPORT(derive_secret_key);

        EMS_EXPORT(generate_key_derivation);

        EMS_EXPORT(generate_key_image);

        EMS_EXPORT(generate_key_image_v2);

        EMS_EXPORT(generate_keys);

        EMS_EXPORT(generate_wallet_seed);

        EMS_EXPORT(generate_wallet_spend_keys);

        EMS_EXPORT(generate_wallet_view_keys);

        EMS_EXPORT(hash_to_point);

        EMS_EXPORT(hash_to_scalar);

        EMS_EXPORT(pow2_round);

        EMS_EXPORT(random_hash);

        EMS_EXPORT(random_hashes);

        EMS_EXPORT(random_point);

        EMS_EXPORT(random_points);

        EMS_EXPORT(random_scalar);

        EMS_EXPORT(random_scalars);

        EMS_EXPORT(restore_wallet_seed);

        EMS_EXPORT(secret_key_to_public_key);

        EMS_EXPORT(underive_public_key);
    }

    // Mapped methods from hashing.cpp
    {
        EMS_EXPORT(argon2d);

        EMS_EXPORT(argon2i);

        EMS_EXPORT(argon2id);

        EMS_EXPORT(sha3);

        EMS_EXPORT(sha3_slow_hash);

        EMS_EXPORT(tree_branch);

        EMS_EXPORT(tree_depth);

        EMS_EXPORT(root_hash);

        EMS_EXPORT(root_hash_from_branch);
    }

    // Mapped methods from mnemonics.cpp
    {
        EMS_EXPORT(mnemonics_calculate_checksum_index);

        EMS_EXPORT(mnemonics_decode);

        EMS_EXPORT(mnemonics_encode);

        EMS_EXPORT(mnemonics_word_index);

        EMS_EXPORT(mnemonics_word_list);

        EMS_EXPORT(mnemonics_word_list_trimmed);
    }

    // Mapped methods from multisig.cpp
    {
        EMS_EXPORT(generate_multisig_secret_key);

        EMS_EXPORT(generate_multisig_secret_keys);

        EMS_EXPORT(generate_shared_public_key);

        EMS_EXPORT(generate_shared_secret_key);

        EMS_EXPORT(rounds_required);
    }

    // Mapped methods from ringct.cpp
    {
        EMS_EXPORT(check_commitments_parity);

        EMS_EXPORT(generate_amount_mask);

        EMS_EXPORT(generate_commitment_blinding_factor);

        EMS_EXPORT(generate_pedersen_commitment);

        EMS_EXPORT(generate_pseudo_commitments);

        EMS_EXPORT(toggle_masked_amount);
    }

    // Mapped methods from ring_signature_borromean.cpp
    {
        EMS_EXPORT(borromean_check_ring_signature);

        EMS_EXPORT(borromean_complete_ring_signature);

        EMS_EXPORT(borromean_generate_partial_signing_scalar);

        EMS_EXPORT(borromean_generate_ring_signature);

        EMS_EXPORT(borromean_prepare_ring_signature);
    }

    // Mapped methods from ring_signature_clsag.cpp
    {
        EMS_EXPORT(clsag_check_ring_signature);

        EMS_EXPORT(clsag_complete_ring_signature);

        EMS_EXPORT(clsag_generate_partial_signing_scalar);

        EMS_EXPORT(clsag_generate_ring_signature);

        EMS_EXPORT(clsag_prepare_ring_signature);
    }

    // Mapped methods from ring_signature_triptych.cpp
    {
        EMS_EXPORT(triptych_check_ring_signature);

        EMS_EXPORT(triptych_complete_ring_signature);

        EMS_EXPORT(triptych_generate_partial_signing_scalar);

        EMS_EXPORT(triptych_generate_ring_signature);

        EMS_EXPORT(triptych_prepare_ring_signature);
    }

    // Mapped methods from signature.cpp
    {
        EMS_EXPORT(check_signature);

        EMS_EXPORT(complete_signature);

        EMS_EXPORT(generate_partial_signing_scalar);

        EMS_EXPORT(generate_signature);

        EMS_EXPORT(prepare_signature);
    }
}
