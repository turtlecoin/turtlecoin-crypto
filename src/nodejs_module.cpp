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

#include <nan.h>
#include <v8.h>

/**
 * A whole bunch of of NAN helper functions to save a lot of typing
 */

template<typename T> static inline v8::Local<T> to_v8_string(const std::string &string)
{
    return Nan::New(string).ToLocalChecked();
}

#define STR_TO_NAN_VAL(string) to_v8_string<v8::Value>(string)
#define STR_TO_NAN_STR(string) to_v8_string<v8::String>(string)
#define NAN_TO_STR(value) \
    std::string(*Nan::Utf8String(value->ToString(Nan::GetCurrentContext()).FromMaybe(v8::Local<v8::String>())));
#define NAN_TO_UINT32(value) Nan::To<uint32_t>(value).FromJust()
#define NAN_TO_UINT64(value) (uint64_t) Nan::To<uint32_t>(value).FromJust()

static inline v8::Local<v8::Array> to_v8_array(const std::vector<std::string> &vector)
{
    auto array = Nan::New<v8::Array>(vector.size());

    for (size_t i = 0; i < vector.size(); ++i)
    {
        Nan::Set(array, i, STR_TO_NAN_VAL(vector[i]));
    }

    return array;
}

template<typename T> static inline v8::Local<v8::Array> to_v8_array(const std::vector<T> &vector)
{
    auto array = Nan::New<v8::Array>(vector.size());

    for (size_t i = 0; i < vector.size(); ++i)
    {
        Nan::Set(array, i, STR_TO_NAN_VAL(vector[i].to_string()));
    }

    return array;
}

template<typename T> static inline v8::Local<v8::Array> to_v8_array(const std::vector<std::vector<T>> &vector)
{
    auto array = Nan::New<v8::Array>(vector.size());

    for (size_t i = 0; i < vector.size(); ++i)
    {
        const auto &level1 = vector[i];

        auto sub_array = Nan::New<v8::Array>();

        for (size_t j = 0; j < level1.size(); ++j)
        {
            Nan::Set(sub_array, j, STR_TO_NAN_VAL(level1[j].to_string()));
        }

        Nan::Set(array, i, sub_array);
    }

    return array;
}

static inline v8::Local<v8::Array> prepare(const bool success, const v8::Local<v8::Value> &val)
{
    v8::Local<v8::Array> result = Nan::New<v8::Array>(2);

    Nan::Set(result, 0, Nan::New(!success));

    Nan::Set(result, 1, val);

    return result;
}

static inline v8::Local<v8::Object> get_object(const v8::Local<v8::Value> &nan_value)
{
    auto result = Nan::New<v8::Object>();

    if (nan_value->IsObject())
    {
        result = v8::Local<v8::Object>::Cast(nan_value);
    }

    return result;
}

static inline v8::Local<v8::Object> get_object(const Nan::FunctionCallbackInfo<v8::Value> &info, const uint8_t index)
{
    v8::Local<v8::Object> result = Nan::New<v8::Object>();

    if (info.Length() >= index)
    {
        result = get_object(info[index]);
    }

    return result;
}

static inline bool object_has(const v8::Local<v8::Object> &obj, const std::string &key)
{
    return Nan::Has(obj, STR_TO_NAN_STR(key)).FromJust();
}

template<typename T> static inline T get(const v8::Local<v8::Value> &nan_value)
{
    T result = T();

    return result;
}

template<> inline std::string get<std::string>(const v8::Local<v8::Value> &nan_value)
{
    auto result = std::string();

    if (nan_value->IsString())
    {
        result = NAN_TO_STR(nan_value);
    }

    return result;
}

template<> inline uint32_t get<uint32_t>(const v8::Local<v8::Value> &nan_value)
{
    uint32_t result = 0;

    if (nan_value->IsNumber())
    {
        result = NAN_TO_UINT32(nan_value);
    }

    return result;
}

template<> inline uint64_t get<uint64_t>(const v8::Local<v8::Value> &nan_value)
{
    uint64_t result = 0;

    if (nan_value->IsNumber())
    {
        result = NAN_TO_UINT64(nan_value);
    }

    return result;
}

template<typename T> static inline T get(const Nan::FunctionCallbackInfo<v8::Value> &info, const uint8_t index)
{
    T result;

    if (info.Length() >= index)
    {
        result = get<T>(info[index]);
    }

    return result;
}

static inline std::string get(const v8::Local<v8::Object> &obj, const std::string &key)
{
    std::string result = std::string();

    if (object_has(obj, key))
    {
        const auto value = Nan::Get(obj, STR_TO_NAN_VAL(key)).ToLocalChecked();

        result = get<std::string>(value);
    }

    return result;
}

template<typename T> static inline T get_crypto_t(const Nan::FunctionCallbackInfo<v8::Value> &info, const uint8_t index)
{
    T result;

    const auto value = get<std::string>(info, index);

    if (!value.empty())
    {
        try
        {
            result = value;
        }
        catch (...)
        {
        }
    }

    return result;
}

template<typename T> static inline T get_crypto_t(const v8::Local<v8::Object> &obj, const std::string &key)
{
    T result;

    const auto value = get(obj, key);

    if (!value.empty())
    {
        result = value;
    }

    return result;
}

template<typename T> static inline std::vector<T> get_vector(const v8::Local<v8::Array> &array)
{
    std::vector<T> results;

    const auto array_size = array->Length();

    for (size_t i = 0; i < array_size; ++i)
    {
        const auto nan_value = Nan::Get(array, i).ToLocalChecked();

        if (nan_value->IsString())
        {
            const auto value = std::string(*Nan::Utf8String(nan_value));

            try
            {
                results.push_back(value);
            }
            catch (...)
            {
            }
        }
    }

    /**
     * If our resulting array size is not what we expected, then something
     * in the array was not what we expected it to be which means that the
     * entire array is garbage
     */
    if (results.size() != array_size)
    {
        results.clear();
    }

    return results;
}

template<> inline std::vector<uint64_t> get_vector<uint64_t>(const v8::Local<v8::Array> &array)
{
    std::vector<uint64_t> results;

    const auto array_size = array->Length();

    for (size_t i = 0; i < array_size; ++i)
    {
        const auto nan_value = Nan::Get(array, i).ToLocalChecked();

        if (nan_value->IsNumber())
        {
            const auto value = (uint64_t)Nan::To<uint32_t>(nan_value).FromJust();

            results.push_back(value);
        }
    }

    /**
     * If our resulting array size is not what we expected, then something
     * in the array was not what we expected it to be which means that the
     * entire array is garbage
     */
    if (results.size() != array_size)
    {
        results.clear();
    }

    return results;
}

template<typename T>
static inline std::vector<T> get_vector(const Nan::FunctionCallbackInfo<v8::Value> &info, const uint8_t index)
{
    std::vector<T> results;

    if (info.Length() >= index)
    {
        if (info[index]->IsArray())
        {
            const auto array = v8::Local<v8::Array>::Cast(info[index]);

            results = get_vector<T>(array);
        }
    }

    return results;
}

template<typename T> static inline std::vector<T> get_vector(const v8::Local<v8::Object> &obj, const std::string &key)
{
    std::vector<T> results;

    if (object_has(obj, key))
    {
        const auto nan_value = Nan::Get(obj, STR_TO_NAN_VAL(key)).ToLocalChecked();

        if (nan_value->IsArray())
        {
            const auto array = v8::Local<v8::Array>::Cast(nan_value);

            results = get_vector<T>(array);
        }
    }

    return results;
}

template<>
inline std::vector<std::vector<crypto_scalar_t>>
    get_vector<std::vector<crypto_scalar_t>>(const v8::Local<v8::Array> &array)
{
    std::vector<std::vector<crypto_scalar_t>> results;

    const auto outer_array_size = array->Length();

    for (size_t i = 0; i < outer_array_size; ++i)
    {
        const auto outer_element = Nan::Get(array, i).ToLocalChecked();

        if (outer_element->IsArray())
        {
            const auto inner_array = v8::Local<v8::Array>::Cast(outer_element);

            const auto inner_elements = get_vector<crypto_scalar_t>(inner_array);

            if (!inner_elements.empty())
            {
                results.push_back(inner_elements);
            }
        }
    }

    /**
     * If our resulting array size is not what we expected, then something
     * in the array was not what we expected it to be which means that the
     * entire array is garbage
     */
    if (results.size() != outer_array_size)
    {
        results.clear();
    }

    return results;
}

template<>
inline std::vector<std::vector<crypto_pedersen_commitment_t>>
    get_vector<std::vector<crypto_pedersen_commitment_t>>(const v8::Local<v8::Array> &array)
{
    std::vector<std::vector<crypto_pedersen_commitment_t>> results;

    const auto outer_array_size = array->Length();

    for (size_t i = 0; i < outer_array_size; ++i)
    {
        const auto outer_element = Nan::Get(array, i).ToLocalChecked();

        if (outer_element->IsArray())
        {
            const auto inner_array = v8::Local<v8::Array>::Cast(outer_element);

            const auto inner_elements = get_vector<crypto_pedersen_commitment_t>(inner_array);

            if (!inner_elements.empty())
            {
                results.push_back(inner_elements);
            }
        }
    }

    /**
     * If our resulting array size is not what we expected, then something
     * in the array was not what we expected it to be which means that the
     * entire array is garbage
     */
    if (results.size() != outer_array_size)
    {
        results.clear();
    }

    return results;
}

/**
 * Mapped methods from base58.cpp
 */

NAN_METHOD(base58_encode)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hex = get<std::string>(info, 0);

    if (!hex.empty())
    {
        try
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::Base58::encode(reader.unread_data());

            result = STR_TO_NAN_VAL(base58);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(base58_encode_check)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hex = get<std::string>(info, 0);

    if (!hex.empty())
    {
        try
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::Base58::encode_check(reader.unread_data());

            result = STR_TO_NAN_VAL(base58);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(base58_decode)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto base58 = get<std::string>(info, 0);

    if (!base58.empty())
    {
        try
        {
            const auto [decode_success, decoded] = Crypto::Base58::decode(base58);

            if (decode_success)
            {
                serializer_t writer;

                writer.bytes(decoded);

                result = STR_TO_NAN_VAL(writer.to_string());

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(base58_decode_check)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto base58 = get<std::string>(info, 0);

    if (!base58.empty())
    {
        try
        {
            const auto [decode_success, decoded] = Crypto::Base58::decode_check(base58);

            if (decode_success)
            {
                serializer_t writer;

                writer.bytes(decoded);

                result = STR_TO_NAN_VAL(writer.to_string());

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from cn_base58.cpp
 */

NAN_METHOD(cn_base58_encode)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hex = get<std::string>(info, 0);

    if (!hex.empty())
    {
        try
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::CNBase58::encode(reader.unread_data());

            result = STR_TO_NAN_VAL(base58);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(cn_base58_encode_check)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hex = get<std::string>(info, 0);

    if (!hex.empty())
    {
        try
        {
            deserializer_t reader(hex);

            const auto base58 = Crypto::CNBase58::encode_check(reader.unread_data());

            result = STR_TO_NAN_VAL(base58);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(cn_base58_decode)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto base58 = get<std::string>(info, 0);

    if (!base58.empty())
    {
        try
        {
            const auto [decode_success, decoded] = Crypto::CNBase58::decode(base58);

            if (decode_success)
            {
                serializer_t writer;

                writer.bytes(decoded);

                result = STR_TO_NAN_VAL(writer.to_string());

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(cn_base58_decode_check)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto base58 = get<std::string>(info, 0);

    if (!base58.empty())
    {
        try
        {
            const auto [decode_success, decoded] = Crypto::CNBase58::decode_check(base58);

            if (decode_success)
            {
                serializer_t writer;

                writer.bytes(decoded);

                result = STR_TO_NAN_VAL(writer.to_string());

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from bulletproofs.cpp
 */

NAN_METHOD(bulletproofs_prove)
{
    auto result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    bool success = false;

    const auto amounts = get_vector<uint64_t>(info, 0);

    const auto blinding_factors = get_vector<crypto_blinding_factor_t>(info, 1);

    auto N = get<uint32_t>(info, 2);

    if (N == 0)
    {
        N = 64;
    }

    if (!amounts.empty() && !blinding_factors.empty())
    {
        try
        {
            const auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove(amounts, blinding_factors, N);

            Nan::Set(result, 0, Nan::New(false));

            JSON_INIT();

            proof.toJSON(writer);

            JSON_DUMP(json);

            Nan::Set(result, 1, STR_TO_NAN_VAL(json));

            Nan::Set(result, 2, to_v8_array(commitments));
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(bulletproofs_verify)
{
    auto result = Nan::New(false);

    const auto proofs_array = get<std::string>(info, 0);

    const auto commitments = get_vector<std::vector<crypto_pedersen_commitment_t>>(info, 1);

    if (!proofs_array.empty() && !commitments.empty())
    {
        try
        {
            std::vector<crypto_bulletproof_t> proofs;

            JSON_PARSE(proofs_array);

            for (const auto &elem : get_json_array(body))
            {
                const auto proof = crypto_bulletproof_t(elem);

                proofs.push_back(proof);
            }

            const auto success = Crypto::RangeProofs::Bulletproofs::verify(proofs, commitments);

            result = Nan::New(success);
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

/**
 * Mapped methods from bulletproofsplus.cpp
 */

NAN_METHOD(bulletproofsplus_prove)
{
    auto result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    bool success = false;

    const auto amounts = get_vector<uint64_t>(info, 0);

    const auto blinding_factors = get_vector<crypto_blinding_factor_t>(info, 1);

    auto N = get<uint32_t>(info, 2);

    if (N == 0)
    {
        N = 64;
    }

    if (!amounts.empty() && !blinding_factors.empty())
    {
        try
        {
            const auto [proof, commitments] =
                Crypto::RangeProofs::BulletproofsPlus::prove(amounts, blinding_factors, N);

            JSON_INIT();

            proof.toJSON(writer);

            JSON_DUMP(json);

            Nan::Set(result, 0, Nan::New(false));

            Nan::Set(result, 1, STR_TO_NAN_VAL(json));

            Nan::Set(result, 2, to_v8_array(commitments));
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(bulletproofsplus_verify)
{
    auto result = Nan::New(false);

    const auto proofs_array = get<std::string>(info, 0);

    const auto commitments = get_vector<std::vector<crypto_pedersen_commitment_t>>(info, 1);

    if (!proofs_array.empty() && !commitments.empty())
    {
        try
        {
            std::vector<crypto_bulletproof_plus_t> proofs;

            JSON_PARSE(proofs_array);

            for (const auto &elem : get_json_array(body))
            {
                const auto proof = crypto_bulletproof_plus_t(elem);

                proofs.push_back(proof);
            }

            const auto success = Crypto::RangeProofs::BulletproofsPlus::verify(proofs, commitments);

            result = Nan::New(success);
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

/**
 * Mapped methods from crypto_common.cpp
 */

NAN_METHOD(calculate_base2_exponent)
{
    auto result = STR_TO_NAN_VAL("");

    const auto value = get<uint32_t>(info, 0);

    const auto [method_success, exponent] = Crypto::calculate_base2_exponent(value);

    if (method_success)
    {
        result = Nan::New(uint32_t(exponent));
    }

    info.GetReturnValue().Set(prepare(method_success, result));
}

NAN_METHOD(check_point)
{
    const auto point = get<std::string>(info, 0);

    const auto success = Crypto::check_point(point);

    info.GetReturnValue().Set(Nan::New(success));
}

NAN_METHOD(check_scalar)
{
    const auto scalar = get<std::string>(info, 0);

    const auto success = Crypto::check_scalar(scalar);

    info.GetReturnValue().Set(Nan::New(success));
}

NAN_METHOD(derivation_to_scalar)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto derivation = get<std::string>(info, 0);

    const auto output_index = get<uint64_t>(info, 1);

    if (!derivation.empty())
    {
        try
        {
            const auto scalar = Crypto::derivation_to_scalar(derivation, output_index);

            result = STR_TO_NAN_VAL(scalar.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(derive_public_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto derivation_scalar = get<std::string>(info, 0);

    const auto public_key = get<std::string>(info, 1);

    if (!derivation_scalar.empty() && !public_key.empty())
    {
        try
        {
            const auto key = Crypto::derive_public_key(derivation_scalar, public_key);

            result = STR_TO_NAN_VAL(key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(derive_secret_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto derivation_scalar = get<std::string>(info, 0);

    const auto secret_key = get<std::string>(info, 1);

    if (!derivation_scalar.empty() && !secret_key.empty())
    {
        try
        {
            const auto key = Crypto::derive_secret_key(derivation_scalar, secret_key);

            result = STR_TO_NAN_VAL(key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_key_derivation)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto public_key = get<std::string>(info, 0);

    const auto secret_key = get<std::string>(info, 1);

    if (!public_key.empty() && !secret_key.empty())
    {
        try
        {
            const auto key = Crypto::generate_key_derivation(public_key, secret_key);

            result = STR_TO_NAN_VAL(key.to_string());

            success = true;
        }
        catch (const std::exception &e)
        {
            std::cout << e.what() << std::endl;
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_key_image)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto public_key = get<std::string>(info, 0);

    const auto secret_key = get<std::string>(info, 1);

    const auto partial_key_images = get_vector<crypto_key_image_t>(info, 2);

    if (!public_key.empty() && !secret_key.empty())
    {
        try
        {
            const auto key = Crypto::generate_key_image(public_key, secret_key, partial_key_images);

            result = STR_TO_NAN_VAL(key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_key_image_v2)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto secret_key = get<std::string>(info, 0);

    if (!secret_key.empty())
    {
        try
        {
            const auto key = Crypto::generate_key_image_v2(secret_key);

            result = STR_TO_NAN_VAL(key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_keys)
{
    auto result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    try
    {
        const auto [public_key, secret_key] = Crypto::generate_keys();

        Nan::Set(result, 0, Nan::New(false));

        Nan::Set(result, 1, STR_TO_NAN_VAL(public_key.to_string()));

        Nan::Set(result, 2, STR_TO_NAN_VAL(secret_key.to_string()));
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(generate_wallet_seed)
{
    auto result = Nan::New<v8::Array>(4);

    Nan::Set(result, 0, Nan::New(true));

    const auto entropy = get<std::string>(info, 0);

    try
    {
        deserializer_t reader(entropy);

        const auto [seed, words, timestamp] = Crypto::generate_wallet_seed(reader.unread_data());

        Nan::Set(result, 0, Nan::New(false));

        Nan::Set(result, 1, STR_TO_NAN_VAL(seed.to_string()));

        Nan::Set(result, 2, to_v8_array(words));

        serializer_t writer;

        writer.uint64(timestamp);

        Nan::Set(result, 3, STR_TO_NAN_VAL(writer.to_string()));
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(generate_wallet_spend_keys)
{
    auto result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    const auto wallet_seed = get<std::string>(info, 0);

    const auto subwallet_index = get<uint64_t>(info, 1);

    if (!wallet_seed.empty())
    {
        try
        {
            const auto [public_key, secret_key] = Crypto::generate_wallet_spend_keys(wallet_seed, subwallet_index);

            Nan::Set(result, 0, Nan::New(false));

            Nan::Set(result, 1, STR_TO_NAN_VAL(public_key.to_string()));

            Nan::Set(result, 2, STR_TO_NAN_VAL(secret_key.to_string()));
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(generate_wallet_view_keys)
{
    auto result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    const auto wallet_seed = get<std::string>(info, 0);

    if (!wallet_seed.empty())
    {
        try
        {
            const auto [public_key, secret_key] = Crypto::generate_wallet_view_keys(wallet_seed);

            Nan::Set(result, 0, Nan::New(false));

            Nan::Set(result, 1, STR_TO_NAN_VAL(public_key.to_string()));

            Nan::Set(result, 2, STR_TO_NAN_VAL(secret_key.to_string()));
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(hash_to_point)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto point = Crypto::hash_to_point(input.data(), sizeof(input.data()));

            result = STR_TO_NAN_VAL(point.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(hash_to_scalar)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto scalar = Crypto::hash_to_scalar(input.data(), sizeof(input.data()));

            result = STR_TO_NAN_VAL(scalar.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(pow2_round)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto input = get<uint32_t>(info, 0);

    try
    {
        const auto value = uint32_t(Crypto::pow2_round(input));

        result = Nan::New(value);

        success = true;
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(random_hash)
{
    v8::Local<v8::Value> result = STR_TO_NAN_VAL(Crypto::random_hash().to_string());

    info.GetReturnValue().Set(prepare(true, result));
}

NAN_METHOD(random_hashes)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto count = get<uint32_t>(info, 0);

    try
    {
        const auto points = Crypto::random_hashes(count);

        result = to_v8_array(points);

        success = true;
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(random_point)
{
    v8::Local<v8::Value> result = STR_TO_NAN_VAL(Crypto::random_point().to_string());

    info.GetReturnValue().Set(prepare(true, result));
}

NAN_METHOD(random_points)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto count = get<uint32_t>(info, 0);

    try
    {
        const auto points = Crypto::random_points(count);

        result = to_v8_array(points);

        success = true;
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(random_scalar)
{
    v8::Local<v8::Value> result = STR_TO_NAN_VAL(Crypto::random_scalar().to_string());

    info.GetReturnValue().Set(prepare(true, result));
}

NAN_METHOD(random_scalars)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto count = get<uint32_t>(info, 0);

    try
    {
        const auto scalars = Crypto::random_scalars(count);

        result = to_v8_array(scalars);

        success = true;
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(secret_key_to_public_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto secret_key = get<std::string>(info, 0);

    if (!secret_key.empty())
    {
        try
        {
            const auto public_key = Crypto::secret_key_to_public_key(secret_key);

            result = STR_TO_NAN_VAL(public_key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(underive_public_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto derivation = get<std::string>(info, 0);

    const auto output_index = get<uint64_t>(info, 1);

    const auto public_ephemeral = get<std::string>(info, 2);

    if (!derivation.empty() && !public_ephemeral.empty())
    {
        try
        {
            const auto public_key = Crypto::underive_public_key(derivation, output_index, public_ephemeral);

            result = STR_TO_NAN_VAL(public_key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from hashing.cpp
 */

NAN_METHOD(argon2d)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    const auto iterations = get<uint64_t>(info, 1);

    const auto memory = get<uint64_t>(info, 2);

    const auto threads = get<uint64_t>(info, 3);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto hash = Crypto::Hashing::argon2d(
                input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);

            result = STR_TO_NAN_VAL(hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(argon2i)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    const auto iterations = get<uint64_t>(info, 1);

    const auto memory = get<uint64_t>(info, 2);

    const auto threads = get<uint64_t>(info, 3);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto hash = Crypto::Hashing::argon2i(
                input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);

            result = STR_TO_NAN_VAL(hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(argon2id)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    const auto iterations = get<uint64_t>(info, 1);

    const auto memory = get<uint64_t>(info, 2);

    const auto threads = get<uint64_t>(info, 3);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto hash = Crypto::Hashing::argon2id(
                input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);

            result = STR_TO_NAN_VAL(hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(sha3)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto hash = Crypto::Hashing::sha3(input.data(), input.size());

            result = STR_TO_NAN_VAL(hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(sha3_slow_hash)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto data = get<std::string>(info, 0);

    const auto iterations = get<uint32_t>(info, 1);

    if (!data.empty())
    {
        try
        {
            const auto input = Crypto::StringTools::from_hex(data);

            const auto hash = Crypto::Hashing::sha3_slow_hash(input.data(), input.size(), iterations);

            result = STR_TO_NAN_VAL(hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(tree_branch)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hashes = get_vector<crypto_hash_t>(info, 0);

    if (!hashes.empty())
    {
        try
        {
            const auto tree_branches = Crypto::Hashing::Merkle::tree_branch(hashes);

            result = to_v8_array(tree_branches);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(tree_depth)
{
    const auto count = get<uint32_t>(info, 0);

    const auto depth = uint32_t(Crypto::Hashing::Merkle::tree_depth(count));

    info.GetReturnValue().Set(prepare(true, Nan::New(depth)));
}

NAN_METHOD(root_hash)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hashes = get_vector<crypto_hash_t>(info, 0);

    if (!hashes.empty())
    {
        try
        {
            const auto root_hash = Crypto::Hashing::Merkle::root_hash(hashes);

            result = STR_TO_NAN_VAL(root_hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(root_hash_from_branch)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto hashes = get_vector<crypto_hash_t>(info, 0);

    const auto depth = get<uint32_t>(info, 1);

    const auto leaf = get<std::string>(info, 2);

    const auto path = get<uint8_t>(info, 3);

    if (!hashes.empty() && !leaf.empty() && path <= 1)
    {
        try
        {
            const auto root_hash = Crypto::Hashing::Merkle::root_hash_from_branch(hashes, depth, leaf, path);

            result = STR_TO_NAN_VAL(root_hash.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from mnemonics.cpp
 */

NAN_METHOD(mnemonics_calculate_checksum_index)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto words = get_vector<std::string>(info, 0);

    if (!words.empty())
    {
        try
        {
            const auto index = uint32_t(Crypto::Mnemonics::calculate_checksum_index(words));

            if (index >= 0)
            {
                result = Nan::New(index);

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(mnemonics_decode)
{
    auto result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    bool success = false;

    const auto words = get_vector<std::string>(info, 0);

    if (!words.empty())
    {
        try
        {
            const auto [decode_success, decoded, timestamp] = Crypto::Mnemonics::decode(words);

            if (decode_success)
            {
                Nan::Set(result, 0, Nan::New(false));

                Nan::Set(result, 1, STR_TO_NAN_VAL(decoded.to_string()));

                serializer_t writer;

                writer.uint64(timestamp);

                Nan::Set(result, 2, STR_TO_NAN_VAL(writer.to_string()));
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(mnemonics_encode)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto seed = get<std::string>(info, 0);

    const auto timestamp_str = get<std::string>(info, 1);

    const auto auto_timestamp = (get<uint64_t>(info, 2) == 1);

    if (!seed.empty())
    {
        try
        {
            deserializer_t reader(timestamp_str);

            const auto timestamp = reader.uint64();

            const auto words = Crypto::Mnemonics::encode(seed, timestamp, auto_timestamp);

            result = to_v8_array(words);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(mnemonics_word_index)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto word = get<std::string>(info, 0);

    if (!word.empty())
    {
        try
        {
            const auto index = uint32_t(Crypto::Mnemonics::word_index(word));

            if (index != -1)
            {
                result = Nan::New(index);

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(mnemonics_word_list)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    try
    {
        const auto words = Crypto::Mnemonics::word_list();

        result = to_v8_array(words);

        success = true;
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(mnemonics_word_list_trimmed)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    try
    {
        const auto words = Crypto::Mnemonics::word_list_trimmed();

        result = to_v8_array(words);

        success = true;
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from multisig.cpp
 */

NAN_METHOD(generate_multisig_secret_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto their_public_key = get<std::string>(info, 0);

    const auto our_secret_key = get<std::string>(info, 1);

    if (!their_public_key.empty() && !our_secret_key.empty())
    {
        try
        {
            const auto secret_key = Crypto::Multisig::generate_multisig_secret_key(their_public_key, our_secret_key);

            result = STR_TO_NAN_VAL(secret_key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_multisig_secret_keys)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto their_public_keys = get_vector<crypto_public_key_t>(info, 0);

    const auto our_secret_key = get<std::string>(info, 1);

    if (!their_public_keys.empty() && !our_secret_key.empty())
    {
        try
        {
            const auto secret_keys = Crypto::Multisig::generate_multisig_secret_keys(their_public_keys, our_secret_key);

            result = to_v8_array(secret_keys);

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_shared_public_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto public_keys = get_vector<crypto_public_key_t>(info, 0);

    if (!public_keys.empty())
    {
        try
        {
            const auto public_key = Crypto::Multisig::generate_shared_public_key(public_keys);

            result = STR_TO_NAN_VAL(public_key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_shared_secret_key)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto secret_keys = get_vector<crypto_secret_key_t>(info, 0);

    if (!secret_keys.empty())
    {
        try
        {
            const auto secret_key = Crypto::Multisig::generate_shared_secret_key(secret_keys);

            result = STR_TO_NAN_VAL(secret_key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(rounds_required)
{
    auto result = STR_TO_NAN_VAL("");

    const auto participants = get<uint32_t>(info, 0);

    const auto threshold = get<uint32_t>(info, 1);

    const auto rounds = uint32_t(Crypto::Multisig::rounds_required(participants, threshold));

    result = Nan::New(rounds);

    info.GetReturnValue().Set(prepare(true, result));
}

/**
 * Mapped methods from ringct.cpp
 */

NAN_METHOD(check_commitments_parity)
{
    bool success = false;

    const auto pseudo_commitments = get_vector<crypto_pedersen_commitment_t>(info, 0);

    const auto output_commitments = get_vector<crypto_pedersen_commitment_t>(info, 1);

    const auto transaction_fee = get<uint64_t>(info, 2);

    try
    {
        success = Crypto::RingCT::check_commitments_parity(pseudo_commitments, output_commitments, transaction_fee);
    }
    catch (...)
    {
    }

    info.GetReturnValue().Set(Nan::New(success));
}

NAN_METHOD(generate_amount_mask)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto derivation_scalar = get<std::string>(info, 0);

    if (!derivation_scalar.empty())
    {
        try
        {
            const auto amount_mask = Crypto::RingCT::generate_amount_mask(derivation_scalar);

            result = STR_TO_NAN_VAL(amount_mask.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_commitment_blinding_factor)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto derivation_scalar = get<std::string>(info, 0);

    if (!derivation_scalar.empty())
    {
        try
        {
            const auto blinding_factor = Crypto::RingCT::generate_commitment_blinding_factor(derivation_scalar);

            result = STR_TO_NAN_VAL(blinding_factor.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_pedersen_commitment)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto blinding_factor = get<std::string>(info, 0);

    const auto amount = get<uint64_t>(info, 1);

    if (!blinding_factor.empty())
    {
        try
        {
            const auto commitment = Crypto::RingCT::generate_pedersen_commitment(blinding_factor, amount);

            result = STR_TO_NAN_VAL(commitment.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_pseudo_commitments)
{
    v8::Local<v8::Array> result = Nan::New<v8::Array>(3);

    Nan::Set(result, 0, Nan::New(true));

    const auto input_amounts = get_vector<uint64_t>(info, 0);

    const auto output_blinding_factors = get_vector<crypto_blinding_factor_t>(info, 1);

    if (!input_amounts.empty() && !output_blinding_factors.empty())
    {
        try
        {
            const auto [blinding_factors, commitments] =
                Crypto::RingCT::generate_pseudo_commitments(input_amounts, output_blinding_factors);

            Nan::Set(result, 0, Nan::New(false));

            Nan::Set(result, 1, to_v8_array(blinding_factors));

            Nan::Set(result, 2, to_v8_array(commitments));
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(toggle_masked_amount)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto amount_mask = get<std::string>(info, 0);

    const auto amount_hex = get<std::string>(info, 1);

    const auto amount = get<uint64_t>(info, 1);

    if (!amount_mask.empty())
    {
        try
        {
            if (!amount_hex.empty())
            {
                const auto amount_bytes = Crypto::StringTools::from_hex(amount_hex);

                const auto masked_amount =
                    Crypto::RingCT::toggle_masked_amount(amount_mask, amount_bytes).to_uint64_t();

                result = STR_TO_NAN_VAL(Crypto::StringTools::to_hex(&masked_amount, sizeof(uint64_t)));

                success = true;
            }
            else
            {
                const auto masked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, amount).to_uint64_t();

                result = STR_TO_NAN_VAL(Crypto::StringTools::to_hex(&masked_amount, sizeof(uint64_t)));

                success = true;
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from ring_signature_borromean.cpp
 */

NAN_METHOD(borromean_check_ring_signature)
{
    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto key_image = get<std::string>(info, 1);

    const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

    const auto signature_obj = get<std::string>(info, 3);

    if (!message_digest.empty() && !key_image.empty() && !public_keys.empty() && !signature_obj.empty())
    {
        try
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_borromean_signature_t(body);

            success = Crypto::RingSignature::Borromean::check_ring_signature(
                message_digest, key_image, public_keys, signature);
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(Nan::New(success));
}

NAN_METHOD(borromean_complete_ring_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto signing_scalar = get<std::string>(info, 0);

    const auto real_output_index = get<uint32_t>(info, 1);

    const auto signature_obj = get<std::string>(info, 2);

    const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 3);

    if (!signing_scalar.empty() && !signature_obj.empty())
    {
        try
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_borromean_signature_t(body);

            const auto [method_success, sig] = Crypto::RingSignature::Borromean::complete_ring_signature(
                signing_scalar, real_output_index, signature, partial_signing_scalars);

            if (method_success)
            {
                JSON_INIT();

                sig.toJSON(writer);

                JSON_DUMP(json);

                result = STR_TO_NAN_VAL(json);
            }

            success = method_success;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(borromean_generate_partial_signing_scalar)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto real_output_index = get<uint32_t>(info, 0);

    const auto signature_obj = get<std::string>(info, 1);

    const auto spend_secret_key = get<std::string>(info, 2);

    if (!signature_obj.empty() && !spend_secret_key.empty())
    {
        try
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_borromean_signature_t(body);

            const auto partial_signing_scalar = Crypto::RingSignature::Borromean::generate_partial_signing_scalar(
                real_output_index, signature, spend_secret_key);

            result = STR_TO_NAN_VAL(partial_signing_scalar.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(borromean_generate_ring_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto secret_ephemeral = get<std::string>(info, 1);

    const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

    if (!message_digest.empty() && !secret_ephemeral.empty() && !public_keys.empty())
    {
        try
        {
            const auto [method_success, signature] = Crypto::RingSignature::Borromean::generate_ring_signature(
                message_digest, secret_ephemeral, public_keys);

            if (method_success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(json);

                result = STR_TO_NAN_VAL(json);
            }

            success = method_success;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(borromean_prepare_ring_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto key_image = get<std::string>(info, 1);

    const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

    const auto real_output_index = get<uint32_t>(info, 3);

    if (!message_digest.empty() && !key_image.empty() && !public_keys.empty())
    {
        try
        {
            const auto [method_success, signature] = Crypto::RingSignature::Borromean::prepare_ring_signature(
                message_digest, key_image, public_keys, real_output_index);

            if (method_success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(json);

                result = STR_TO_NAN_VAL(json);
            }

            success = method_success;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

/**
 * Mapped methods from ring_signature_clsag.cpp
 */

NAN_METHOD(clsag_check_ring_signature)
{
    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto key_image = get<std::string>(info, 1);

    const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

    const auto signature_obj = get<std::string>(info, 3);

    const auto commitments = get_vector<crypto_pedersen_commitment_t>(info, 4);

    if (!message_digest.empty() && !key_image.empty() && !public_keys.empty() && !signature_obj.empty())
    {
        try
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_clsag_signature_t(body);

            success = Crypto::RingSignature::CLSAG::check_ring_signature(
                message_digest, key_image, public_keys, signature, commitments);
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(Nan::New(success));
}

NAN_METHOD(clsag_complete_ring_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto signing_scalar = get<std::string>(info, 0);

    const auto real_output_index = get<uint32_t>(info, 1);

    const auto signature_obj = get<std::string>(info, 2);

    const auto h = get_vector<crypto_scalar_t>(info, 3);

    const auto mu_P = get<std::string>(info, 4);

    const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 5);

    if (!signing_scalar.empty() && !h.empty() && !mu_P.empty())
    {
        try
        {
            JSON_PARSE(signature_obj);

            const auto signature = crypto_clsag_signature_t(body);

            const auto [method_success, sig] = Crypto::RingSignature::CLSAG::complete_ring_signature(
                signing_scalar, real_output_index, signature, h, mu_P, partial_signing_scalars);

            if (method_success)
            {
                JSON_INIT();

                sig.toJSON(writer);

                JSON_DUMP(json);

                result = STR_TO_NAN_VAL(json);
            }

            success = method_success;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(clsag_generate_partial_signing_scalar)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto mu_P = get<std::string>(info, 0);

    const auto spend_secret_key = get<std::string>(info, 1);

    if (!mu_P.empty() && !spend_secret_key.empty())
    {
        try
        {
            const auto partial_signing_key =
                Crypto::RingSignature::CLSAG::generate_partial_signing_scalar(mu_P, spend_secret_key);

            result = STR_TO_NAN_VAL(partial_signing_key.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(clsag_generate_ring_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto secret_ephemeral = get<std::string>(info, 1);

    const auto public_keys = get_vector<crypto_public_key_t>(info, 2);

    const auto input_blinding_factor = get_crypto_t<crypto_blinding_factor_t>(info, 3);

    const auto public_commitments = get_vector<crypto_pedersen_commitment_t>(info, 4);

    const auto pseudo_blinding_factor = get_crypto_t<crypto_blinding_factor_t>(info, 5);

    const auto pseudo_commitment = get_crypto_t<crypto_pedersen_commitment_t>(info, 6);

    if (!message_digest.empty() && !secret_ephemeral.empty() && !public_keys.empty())
    {
        try
        {
            const auto [method_success, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
                message_digest,
                secret_ephemeral,
                public_keys,
                input_blinding_factor,
                public_commitments,
                pseudo_blinding_factor,
                pseudo_commitment);

            if (method_success)
            {
                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(json);

                result = STR_TO_NAN_VAL(json);
            }

            success = method_success;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(clsag_prepare_ring_signature)
{
    v8::Local<v8::Array> result = Nan::New<v8::Array>(4);

    Nan::Set(result, 0, Nan::New(true));

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
        try
        {
            const auto [method_success, signature, h, mu_P] = Crypto::RingSignature::CLSAG::prepare_ring_signature(
                message_digest,
                key_image,
                public_keys,
                real_output_index,
                input_blinding_factor,
                public_commitments,
                pseudo_blinding_factor,
                pseudo_commitment);

            if (method_success)
            {
                Nan::Set(result, 0, Nan::New(false));

                JSON_INIT();

                signature.toJSON(writer);

                JSON_DUMP(json);

                Nan::Set(result, 1, STR_TO_NAN_VAL(json));

                Nan::Set(result, 2, to_v8_array(h));

                Nan::Set(result, 3, STR_TO_NAN_VAL(mu_P.to_string()));
            }
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

/**
 * Mapped methods from signature.cpp
 */

NAN_METHOD(check_signature)
{
    auto result = Nan::New(false);

    const auto message_digest = get<std::string>(info, 0);

    const auto public_key = get<std::string>(info, 1);

    const auto signature = get<std::string>(info, 2);

    if (!message_digest.empty() && !public_key.empty() && !signature.empty())
    {
        try
        {
            const auto success = Crypto::Signature::check_signature(message_digest, public_key, signature);

            result = Nan::New(success);
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(result);
}

NAN_METHOD(complete_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto signing_scalar = get<std::string>(info, 0);

    const auto signature = get<std::string>(info, 1);

    const auto partial_signing_scalars = get_vector<crypto_scalar_t>(info, 2);

    if (!signing_scalar.empty() && !signature.empty())
    {
        try
        {
            const auto sig = Crypto::Signature::complete_signature(signing_scalar, signature, partial_signing_scalars);

            result = STR_TO_NAN_VAL(sig.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_partial_signing_scalar)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto signature = get<std::string>(info, 0);

    const auto spend_secret_key = get<std::string>(info, 1);

    if (!signature.empty() && !spend_secret_key.empty())
    {
        try
        {
            const auto partial_signing_scalar =
                Crypto::Signature::generate_partial_signing_scalar(signature, spend_secret_key);

            result = STR_TO_NAN_VAL(partial_signing_scalar.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(generate_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto secret_key = get<std::string>(info, 1);

    if (!message_digest.empty() && !secret_key.empty())
    {
        try
        {
            const auto signature = Crypto::Signature::generate_signature(message_digest, secret_key);

            result = STR_TO_NAN_VAL(signature.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_METHOD(prepare_signature)
{
    auto result = STR_TO_NAN_VAL("");

    bool success = false;

    const auto message_digest = get<std::string>(info, 0);

    const auto public_key = get<std::string>(info, 1);

    if (!message_digest.empty() && !public_key.empty())
    {
        try
        {
            const auto signature = Crypto::Signature::prepare_signature(message_digest, public_key);

            result = STR_TO_NAN_VAL(signature.to_string());

            success = true;
        }
        catch (...)
        {
        }
    }

    info.GetReturnValue().Set(prepare(success, result));
}

NAN_MODULE_INIT(InitModule)
{
    // Mapped methods from base58.cpp
    {
        NAN_EXPORT(target, base58_encode);

        NAN_EXPORT(target, base58_encode_check);

        NAN_EXPORT(target, base58_decode);

        NAN_EXPORT(target, base58_decode_check);
    }

    // Mapped methods from cn_base58.cpp
    {
        NAN_EXPORT(target, cn_base58_encode);

        NAN_EXPORT(target, cn_base58_encode_check);

        NAN_EXPORT(target, cn_base58_decode);

        NAN_EXPORT(target, cn_base58_decode_check);
    }

    // Mapped methods from bulletproofs.cpp
    {
        NAN_EXPORT(target, bulletproofs_prove);

        NAN_EXPORT(target, bulletproofs_verify);
    }

    // Mapped methods from bulletproofsplus.cpp
    {
        NAN_EXPORT(target, bulletproofsplus_prove);

        NAN_EXPORT(target, bulletproofsplus_verify);
    }

    // Mapped methods from crypto_common.cpp
    {
        NAN_EXPORT(target, calculate_base2_exponent);

        NAN_EXPORT(target, check_point);

        NAN_EXPORT(target, check_scalar);

        NAN_EXPORT(target, derivation_to_scalar);

        NAN_EXPORT(target, derive_public_key);

        NAN_EXPORT(target, derive_secret_key);

        NAN_EXPORT(target, generate_key_derivation);

        NAN_EXPORT(target, generate_key_image);

        NAN_EXPORT(target, generate_key_image_v2);

        NAN_EXPORT(target, generate_keys);

        NAN_EXPORT(target, generate_wallet_seed);

        NAN_EXPORT(target, generate_wallet_spend_keys);

        NAN_EXPORT(target, generate_wallet_view_keys);

        NAN_EXPORT(target, hash_to_point);

        NAN_EXPORT(target, hash_to_scalar);

        NAN_EXPORT(target, pow2_round);

        NAN_EXPORT(target, random_hash);

        NAN_EXPORT(target, random_hashes);

        NAN_EXPORT(target, random_point);

        NAN_EXPORT(target, random_points);

        NAN_EXPORT(target, random_scalar);

        NAN_EXPORT(target, random_scalars);

        NAN_EXPORT(target, secret_key_to_public_key);

        NAN_EXPORT(target, underive_public_key);
    }

    // Mapped methods from hashing.cpp
    {
        NAN_EXPORT(target, argon2d);

        NAN_EXPORT(target, argon2i);

        NAN_EXPORT(target, argon2id);

        NAN_EXPORT(target, sha3);

        NAN_EXPORT(target, sha3_slow_hash);

        NAN_EXPORT(target, tree_branch);

        NAN_EXPORT(target, tree_depth);

        NAN_EXPORT(target, root_hash);

        NAN_EXPORT(target, root_hash_from_branch);
    }

    // Mapped methods from mnemonics.cpp
    {
        NAN_EXPORT(target, mnemonics_calculate_checksum_index);

        NAN_EXPORT(target, mnemonics_decode);

        NAN_EXPORT(target, mnemonics_encode);

        NAN_EXPORT(target, mnemonics_word_index);

        NAN_EXPORT(target, mnemonics_word_list);

        NAN_EXPORT(target, mnemonics_word_list_trimmed);
    }

    // Mapped methods from multisig.cpp
    {
        NAN_EXPORT(target, generate_multisig_secret_key);

        NAN_EXPORT(target, generate_multisig_secret_keys);

        NAN_EXPORT(target, generate_shared_public_key);

        NAN_EXPORT(target, generate_shared_secret_key);

        NAN_EXPORT(target, rounds_required);
    }

    // Mapped methods from ringct.cpp
    {
        NAN_EXPORT(target, check_commitments_parity);

        NAN_EXPORT(target, generate_amount_mask);

        NAN_EXPORT(target, generate_commitment_blinding_factor);

        NAN_EXPORT(target, generate_pedersen_commitment);

        NAN_EXPORT(target, generate_pseudo_commitments);

        NAN_EXPORT(target, toggle_masked_amount);
    }

    // Mapped methods from ring_signature_borromean.cpp
    {
        NAN_EXPORT(target, borromean_check_ring_signature);

        NAN_EXPORT(target, borromean_complete_ring_signature);

        NAN_EXPORT(target, borromean_generate_partial_signing_scalar);

        NAN_EXPORT(target, borromean_generate_ring_signature);

        NAN_EXPORT(target, borromean_prepare_ring_signature);
    }

    // Mapped methods from ring_signature_clsag.cpp
    {
        NAN_EXPORT(target, clsag_check_ring_signature);

        NAN_EXPORT(target, clsag_complete_ring_signature);

        NAN_EXPORT(target, clsag_generate_partial_signing_scalar);

        NAN_EXPORT(target, clsag_generate_ring_signature);

        NAN_EXPORT(target, clsag_prepare_ring_signature);
    }

    // Mapped methods from signature.cpp
    {
        NAN_EXPORT(target, check_signature);

        NAN_EXPORT(target, complete_signature);

        NAN_EXPORT(target, generate_partial_signing_scalar);

        NAN_EXPORT(target, generate_signature);

        NAN_EXPORT(target, prepare_signature);
    }
}

NODE_MODULE(cryptography, InitModule);
