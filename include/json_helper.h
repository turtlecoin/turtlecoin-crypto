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
// Inspired by the work of Zpalmtree found at
// https://github.com/turtlecoin/turtlecoin/blob/cab5c65d243878dc0c9e1ac964614e8e431b6c77/include/JsonHelper.h

#ifndef CRYPTO_JSON_HELPER_H
#define CRYPTO_JSON_HELPER_H

#include <document.h>
#include <reader.h>
#include <stdexcept>
#include <stringbuffer.h>
#include <writer.h>

/**
 * JSON Helpers for repetitive code
 */
#define JSON_OBJECT_OR_THROW()                                          \
    if (!j.IsObject())                                                  \
    {                                                                   \
        throw std::invalid_argument("JSON value is of the wrong type"); \
    }
#define JSON_MEMBER_OR_THROW(value)                                                    \
    if (!has_member(j, std::string(value)))                                            \
    {                                                                                  \
        throw std::invalid_argument(std::string(value) + " not found in JSON object"); \
    }
#define JSON_IF_MEMBER(field) if (has_member(j, #field))
#define JSON_OBJECT_CONSTRUCTORS(objtype, funccall)       \
    objtype(const JSONValue &j)                           \
    {                                                     \
        JSON_OBJECT_OR_THROW()                            \
        funccall(j);                                      \
    }                                                     \
                                                          \
    objtype(const JSONValue &val, const std::string &key) \
    {                                                     \
        const auto &j = get_json_value(val, key);         \
        JSON_OBJECT_OR_THROW()                            \
        funccall(j);                                      \
    }
#define JSON_FROM_FUNC(name) void name(const JSONValue &j)
#define JSON_TO_FUNC(name) void name(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
#define JSON_INIT()                 \
    rapidjson::StringBuffer buffer; \
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer)
#define JSON_INIT_BUFFER(buffer, writer) \
    rapidjson::StringBuffer buffer;      \
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer)
#define JSON_DUMP(str) const std::string str = buffer.GetString()
#define JSON_DUMP_BUFFER(buffer, str) const std::string str = (buffer).GetString()
#define JSON_PARSE(json)                                     \
    rapidjson::Document body;                                \
    if (body.Parse((json).c_str()).HasParseError())          \
    {                                                        \
        throw std::invalid_argument("Could not parse JSON"); \
    }
#define STR_TO_JSON(str, body)                               \
    rapidjson::Document body;                                \
    if ((body).Parse((str).c_str()).HasParseError())         \
    {                                                        \
        throw std::invalid_argument("Could not parse JSON"); \
    }
#define LOAD_KEY_FROM_JSON(field)             \
    {                                         \
        JSON_MEMBER_OR_THROW(#field)          \
                                              \
        (field) = get_json_string(j, #field); \
    }
#define LOAD_KEYV_FROM_JSON(field)                         \
    {                                                      \
        JSON_MEMBER_OR_THROW(#field)                       \
        (field).clear();                                   \
        for (const auto &elem : get_json_array(j, #field)) \
        {                                                  \
            (field).emplace_back(get_json_string(elem));   \
        }                                                  \
    }
#define LOAD_KEYVV_FROM_JSON(field)                          \
    {                                                        \
        JSON_MEMBER_OR_THROW(#field)                         \
        (field).clear();                                     \
        for (const auto &level1 : get_json_array(j, #field)) \
        {                                                    \
            (field).resize((field).size() + 1);              \
            auto &inner = (field).back();                    \
            for (const auto &elem : get_json_array(level1))  \
            {                                                \
                inner.emplace_back(get_json_string(elem));   \
            }                                                \
        }                                                    \
    }
#define LOAD_U64_FROM_JSON(field)               \
    {                                           \
        JSON_MEMBER_OR_THROW(#field);           \
        (field) = get_json_uint64_t(j, #field); \
    }
#define LOAD_U32_FROM_JSON(field)               \
    {                                           \
        JSON_MEMBER_OR_THROW(#field);           \
        (field) = get_json_uint32_t(j, #field); \
    }
#define KEY_TO_JSON(field)      \
    {                           \
        writer.Key(#field);     \
        (field).toJSON(writer); \
    }
#define KEYV_TO_JSON(field)                 \
    {                                       \
        writer.Key(#field);                 \
        writer.StartArray();                \
        {                                   \
            for (const auto &val : (field)) \
            {                               \
                val.toJSON(writer);         \
            }                               \
        }                                   \
        writer.EndArray();                  \
    }
#define KEYVV_TO_JSON(field)                       \
    {                                              \
        writer.Key(#field);                        \
        writer.StartArray();                       \
        {                                          \
            for (const auto &level1 : (field))     \
            {                                      \
                writer.StartArray();               \
                {                                  \
                    for (const auto &val : level1) \
                    {                              \
                        val.toJSON(writer);        \
                    }                              \
                }                                  \
                writer.EndArray();                 \
            }                                      \
        }                                          \
        writer.EndArray();                         \
    }
#define U64_TO_JSON(field)    \
    {                         \
        writer.Key(#field);   \
        writer.Uint64(field); \
    }
#define U32_TO_JSON(field)  \
    {                       \
        writer.Key(#field); \
        writer.Uint(field); \
    }


typedef rapidjson::GenericObject<
    true,
    rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>>
    JSONObject;

typedef rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>
    JSONValue;

static const std::string kTypeNames[] = {"Null", "False", "True", "Object", "Array", "String", "Number", "Double"};

/**
 * Checks if the specified property is in the value/document provided
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> bool has_member(const T &j, const std::string &key)
{
    const auto val = j.FindMember(key);

    return val != j.MemberEnd();
}

/**
 * Retrieves the value at the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> const rapidjson::Value &get_json_value(const T &j, const std::string &key)
{
    const auto val = j.FindMember(key);

    if (val == j.MemberEnd())
    {
        throw std::invalid_argument("Missing JSON parameter: '" + key + "'");
    }

    return val->value;
}

/**
 * Retrieves a boolean from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> bool get_json_bool(const T &j)
{
    if (!j.IsBool())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected bool, got " + kTypeNames[j.GetType()]);
    }

    return j.GetBool();
}

/**
 * Retrieves a boolean from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> bool get_json_bool(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_bool(val);
}

/**
 * Retrieves an int64_t from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> int64_t get_json_int64_t(const T &j)
{
    if (!j.IsInt64())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected int64_t, got " + kTypeNames[j.GetType()]);
    }

    return j.GetInt64();
}

/**
 * Retrieves an int64_t from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> int64_t get_json_int64_t(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_int64_t(val);
}

/**
 * Retrieves an uint64_t from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> uint64_t get_json_uint64_t(const T &j)
{
    if (!j.IsUint64())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected uint64_t, got " + kTypeNames[j.GetType()]);
    }

    return j.GetUint64();
}

/**
 * Retrieves an uint64_t from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> uint64_t get_json_uint64_t(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_uint64_t(val);
}

/**
 * Retrieves an uint32_t from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> uint32_t get_json_uint32_t(const T &j)
{
    if (!j.IsUint())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected uint32_t, got " + kTypeNames[j.GetType()]);
    }

    return j.GetUint();
}

/**
 * Retrieves an uint32_t from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> uint32_t get_json_uint32_t(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_uint32_t(val);
}

/**
 * Retrieves a double from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> double get_json_double(const T &j)
{
    if (!j.IsDouble())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected double, got " + kTypeNames[j.GetType()]);
    }

    return j.GetDouble();
}

/**
 * Retrieves a double from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> double get_json_double(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_double(val);
}

/**
 * Retrieves a std::string from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> std::string get_json_string(const T &j)
{
    if (!j.IsString())
    {
        throw std::invalid_argument(
            "JSON parameter is wrong type. Expected std::string, got " + kTypeNames[j.GetType()]);
    }

    return j.GetString();
}

/**
 * Retrieves a std::string from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> std::string get_json_string(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_string(val);
}

/**
 * Retrieves an array from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> auto get_json_array(const T &j)
{
    if (!j.IsArray())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected Array, got " + kTypeNames[j.GetType()]);
    }

    return j.GetArray();
}

/**
 * Retrieves an array from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> auto get_json_array(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_array(val);
}

/**
 * Retrieves an object from the given value
 * @tparam T
 * @param j
 * @return
 */
template<typename T> JSONObject get_json_object(const T &j)
{
    if (!j.IsObject())
    {
        throw std::invalid_argument("JSON parameter is wrong type. Expected Object, got " + kTypeNames[j.GetType()]);
    }

    return j.Get_Object();
}

/**
 * Retrieves an object from the value in the given property
 * @tparam T
 * @param j
 * @param key
 * @return
 */
template<typename T> JSONObject get_json_object(const T &j, const std::string &key)
{
    const auto &val = get_json_value(j, key);

    return get_json_object(val);
}

#endif // CRYPTO_JSON_HELPER_H
