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

#ifndef CRYPTO_SERIALIZER_H
#define CRYPTO_SERIALIZER_H

#include "string_tools.h"

#include <cmath>
#include <uint256_t.h>

namespace SerializerTools
{
    /**
     * Packs the provided value into a byte vector
     * @tparam T
     * @param value
     * @param big_endian
     * @return
     */
    template<typename T> static inline std::vector<uint8_t> pack(const T &value, bool big_endian = false)
    {
        uint8_t bytes[64] = {0};

        std::memcpy(&bytes, &value, sizeof(T));

        auto result = std::vector<uint8_t>(bytes, bytes + sizeof(T));

        if (big_endian)
        {
            std::reverse(result.begin(), result.end());
        }

        return result;
    }

    /**
     * Unpacks a value from the provided byte vector starting at the given offset
     * @tparam T
     * @param packed
     * @param offset
     * @param big_endian
     * @return
     */
    template<typename T>
    static inline T unpack(const std::vector<uint8_t> &packed, size_t offset = 0, bool big_endian = false)
    {
        const auto size = sizeof(T);

        if (offset + size > packed.size())
        {
            throw std::range_error("not enough data to complete request");
        }

        std::vector<uint8_t> bytes(size, 0);

        for (size_t i = offset, j = 0; i < offset + size; ++i, ++j)
        {
            bytes[j] = packed[i];
        }

        T value = 0;

        if (big_endian)
        {
            std::reverse(bytes.begin(), bytes.end());
        }

        std::memcpy(&value, bytes.data(), bytes.size());

        return value;
    }

    /**
     * Encodes a value into a varint byte vector
     * @tparam T
     * @param value
     * @return
     */
    template<typename T> static inline std::vector<uint8_t> encode_varint(const T &value)
    {
        const auto max_length = sizeof(T) + 2;

        std::vector<uint8_t> output;

        T val = value;

        while (val >= 0x80)
        {
            if (output.size() == (max_length - 1))
            {
                throw std::range_error("value is out of range for type");
            }

            const auto val8 = static_cast<uint8_t>(val);

            output.push_back((static_cast<char>(val8) & 0x7f) | 0x80);

            val >>= 7;
        }

        const auto val8 = static_cast<uint8_t>(val);

        output.push_back(static_cast<char>(val8));

        return output;
    }

    /**
     * Decodes a value from the provided varint byte vector starting at the given offset
     * @tparam T
     * @param packed
     * @param offset
     * @return
     */
    template<typename T>
    static inline std::tuple<T, size_t> decode_varint(const std::vector<uint8_t> &packed, const size_t offset = 0)
    {
        if (offset > packed.size())
        {
            throw std::range_error("offset exceeds sizes of vector");
        }

        auto counter = offset;

        auto shift = 0;

        T temp_result = 0;

        unsigned char b;

        do
        {
            if (counter >= packed.size())
            {
                throw std::range_error("could not decode varint");
            }

            b = packed[counter++];

            const auto value = (shift < 28) ? uint64_t(b & 0x7f) << shift : uint64_t(b & 0x7f) * (uint64_t(1) << shift);

            temp_result += T(value);

            shift += 7;
        } while (b >= 0x80);

        const auto result = T(temp_result);

        if (result != temp_result)
        {
            throw std::range_error("value is out of range for type");
        }

        return {result, counter - offset};
    }
} // namespace SerializerTools

struct serializer_t
{
    serializer_t() {}

    serializer_t(const serializer_t &writer)
    {
        buffer = writer.vector();
    }

    serializer_t(std::initializer_list<uint8_t> input)
    {
        buffer = std::vector<uint8_t>(input);
    }

    serializer_t(const std::vector<uint8_t> &input)
    {
        buffer = input;
    }

    unsigned char &operator[](int i)
    {
        return buffer[i];
    }

    unsigned char operator[](int i) const
    {
        return buffer[i];
    }

    /**
     * Encodes the value into the vector
     * @param value
     */
    void boolean(const bool value)
    {
        if (value)
        {
            buffer.push_back(1);
        }
        else
        {
            buffer.push_back(0);
        }
    }

    /**
     * Encodes the value into the vector
     * @param data
     * @param length
     */
    void bytes(const void *data, size_t length)
    {
        auto const *raw = static_cast<uint8_t const *>(data);

        for (size_t i = 0; i < length; ++i)
        {
            buffer.push_back(raw[i]);
        }
    }

    /**
     * Encodes the value into the vector
     * @param value
     */
    void bytes(const std::vector<uint8_t> &value)
    {
        extend(value);
    }

    /**
     * Returns a pointer to the underlying structure data
     * @return
     */
    [[nodiscard]] const uint8_t *data() const
    {
        return buffer.data();
    }

    /**
     * Encodes the value into the vector
     * @param value
     */
    void hex(const std::string &value)
    {
        const auto bytes = Crypto::StringTools::from_hex(value);

        extend(bytes);
    }

    /**
     * Encodes the value into the vector
     * @tparam T
     * @param value
     */
    template<typename T> void key(const T &value)
    {
        for (size_t i = 0; i < value.size(); ++i)
        {
            buffer.push_back(value[int(i)]);
        }
    }

    /**
     * Encodes the vector of values into the vector
     * @tparam T
     * @param values
     */
    template<typename T> void key(const std::vector<T> &values)
    {
        varint(values.size());

        for (const auto &value : values)
        {
            key(value);
        }
    }

    /**
     * Encodes the nested vector of values into the vector
     * @tparam T
     * @param values
     */
    template<typename T> void key(const std::vector<std::vector<T>> &values)
    {
        varint(values.size());

        for (const auto &level1 : values)
        {
            varint(level1.size());

            for (const auto &value : level1)
            {
                key(value);
            }
        }
    }

    /**
     * Clears the underlying byte vector
     */
    void reset()
    {
        buffer.clear();
    }

    /**
     * Use this method instead of sizeof() to get the resulting
     * size of the structure in bytes
     * @return
     */
    [[nodiscard]] size_t const size() const
    {
        return buffer.size();
    }

    /**
     * Returns the hex encoding of the underlying byte vector
     * @return
     */
    [[nodiscard]] std::string to_string() const
    {
        return Crypto::StringTools::to_hex(buffer.data(), buffer.size());
    }

    /**
     * Encodes the value into the vector
     * @param value
     */
    void uint8(const uint8_t &value)
    {
        buffer.push_back(value);
    }

    /**
     * Encodes the value into the vector
     * @param value
     * @param big_endian
     */
    void uint16(const uint16_t &value, bool big_endian = false)
    {
        const auto packed = SerializerTools::pack(value, big_endian);

        extend(packed);
    }

    /**
     * Encodes the value into the vector
     * @param value
     * @param big_endian
     */
    void uint32(const uint32_t &value, bool big_endian = false)
    {
        const auto packed = SerializerTools::pack(value, big_endian);

        extend(packed);
    }

    /**
     * Encodes the value into the vector
     * @param value
     * @param big_endian
     */
    void uint64(const uint64_t &value, bool big_endian = false)
    {
        const auto packed = SerializerTools::pack(value, big_endian);

        extend(packed);
    }

    /**
     * Encodes the value into the vector
     * @param value
     * @param big_endian
     */
    void uint128(const uint128_t &value, bool big_endian = false)
    {
        const auto packed = SerializerTools::pack(value, big_endian);

        extend(packed);
    }

    /**
     * Encodes the value into the vector
     * @param value
     * @param big_endian
     */
    void uint256(const uint256_t &value, bool big_endian = false)
    {
        const auto packed = SerializerTools::pack(value, big_endian);

        extend(packed);
    }

    /**
     * Encodes the value into the vector as a varint
     * @tparam T
     * @param value
     */
    template<typename T> void varint(const T &value)
    {
        const auto bytes = SerializerTools::encode_varint(value);

        extend(bytes);
    }

    /**
     * Encodes the vector of values into the vector as a varint
     * @tparam T
     * @param values
     */
    template<typename T> void varint(const std::vector<T> &values)
    {
        varint(values.size());

        for (const auto &value : values)
        {
            varint(value);
        }
    }

    /**
     * Returns a copy of the underlying vector
     * @return
     */
    [[nodiscard]] std::vector<uint8_t> vector() const
    {
        return buffer;
    }

  private:
    std::vector<uint8_t> buffer;

    void extend(const std::vector<uint8_t> &vector)
    {
        for (const auto &element : vector)
        {
            buffer.push_back(element);
        }
    }
};

struct deserializer_t
{
    deserializer_t(const serializer_t &writer)
    {
        buffer = writer.vector();
    }

    deserializer_t(std::initializer_list<uint8_t> input)
    {
        buffer = std::vector<uint8_t>(input.begin(), input.end());
    }

    deserializer_t(const std::vector<uint8_t> &input)
    {
        buffer = input;
    }

    deserializer_t(const std::string &input)
    {
        buffer = Crypto::StringTools::from_hex(input);
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @return
     */
    bool boolean(bool peek = false)
    {
        return uint8(peek) == 1;
    }

    /**
     * Returns a byte vector of the given length from the byte vector
     * @param count
     * @param peek
     * @return
     */
    std::vector<uint8_t> bytes(size_t count = 1, bool peek = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += count;
        }

        return std::vector<uint8_t>(buffer.begin() + start, buffer.begin() + start + count);
    }

    /**
     * Trims read dead from the byte vector thus reducing its memory footprint
     */
    void compact()
    {
        buffer = std::vector<uint8_t>(buffer.begin() + offset, buffer.end());
    }

    /**
     * Returns a pointer to the underlying structure data
     * @return
     */
    [[nodiscard]] const uint8_t *data() const
    {
        return buffer.data();
    }

    /**
     * Decodes a hex encoded string of the given length from the byte vector
     * @param length
     * @param peek
     * @return
     */
    std::string hex(size_t length = 1, bool peek = false)
    {
        const auto temp = bytes(length, peek);

        return Crypto::StringTools::to_hex(temp.data(), temp.size());
    }

    /**
     * Decodes a value from the byte vector
     * @tparam T
     * @param peek
     * @return
     */
    template<typename T> T key(bool peek = false)
    {
        T result;

        result = bytes(result.size(), peek);

        return result;
    }

    /**
     * Decodes a vector of values from the byte vector
     * @tparam T
     * @param peek
     * @return
     */
    template<typename T> std::vector<T> keyV(bool peek = false)
    {
        const auto start = offset;

        const auto count = varint<uint64_t>();

        std::vector<T> result;

        const T temp;

        for (uint64_t i = 0; i < count; ++i)
        {
            result.push_back(bytes(temp.size()));
        }

        if (peek)
        {
            offset = start;
        }

        return result;
    }

    /**
     * Decodes a nested vector of values from the byte vector
     * @tparam T
     * @param peek
     * @return
     */
    template<typename T> std::vector<std::vector<T>> keyVV(bool peek = false)
    {
        const auto start = offset;

        const auto level1_count = varint<uint64_t>();

        std::vector<std::vector<T>> result;

        for (uint64_t i = 0; i < level1_count; ++i)
        {
            const auto count = varint<uint64_t>();

            std::vector<T> temp;

            for (uint64_t j = 0; j < count; ++j)
            {
                temp.push_back(key<T>());
            }

            result.push_back(temp);
        }

        if (peek)
        {
            offset = start;
        }

        return result;
    }

    /**
     * Resets the reader to the given position (default 0)
     * @param position
     */
    void reset(size_t position = 0)
    {
        offset = position;
    }

    /**
     * Use this method instead of sizeof() to get the resulting
     * size of the structure in bytes
     * @return
     */
    [[nodiscard]] size_t size() const
    {
        return buffer.size();
    }

    /**
     * Skips the next specified bytes while reading
     * @param count
     */
    void skip(size_t count = 1)
    {
        offset += count;
    }

    /**
     * Returns the hex encoding of the underlying byte vector
     * @return
     */
    [[nodiscard]] std::string to_string() const
    {
        return Crypto::StringTools::to_hex(buffer.data(), buffer.size());
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @return
     */
    uint8_t uint8(bool peek = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += sizeof(uint8_t);
        }

        return SerializerTools::unpack<uint8_t>(buffer, start);
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @param big_endian
     * @return
     */
    uint16_t uint16(bool peek = false, bool big_endian = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += sizeof(uint16_t);
        }

        return SerializerTools::unpack<uint16_t>(buffer, start, big_endian);
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @param big_endian
     * @return
     */
    uint32_t uint32(bool peek = false, bool big_endian = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += sizeof(uint32_t);
        }

        return SerializerTools::unpack<uint32_t>(buffer, start, big_endian);
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @param big_endian
     * @return
     */
    uint64_t uint64(bool peek = false, bool big_endian = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += sizeof(uint64_t);
        }

        return SerializerTools::unpack<uint64_t>(buffer, start, big_endian);
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @param big_endian
     * @return
     */
    uint128_t uint128(bool peek = false, bool big_endian = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += sizeof(uint128_t);
        }

        return SerializerTools::unpack<uint128_t>(buffer, start, big_endian);
    }

    /**
     * Decodes a value from the byte vector
     * @param peek
     * @param big_endian
     * @return
     */
    uint256_t uint256(bool peek = false, bool big_endian = false)
    {
        const auto start = offset;

        if (!peek)
        {
            offset += sizeof(uint256_t);
        }

        return SerializerTools::unpack<uint256_t>(buffer, start, big_endian);
    }

    /**
     * Decodes a value from the byte vector
     * @tparam T
     * @param peek
     * @return
     */
    template<typename T> T varint(bool peek = false)
    {
        const auto start = offset;

        const auto [result, length] = SerializerTools::decode_varint<T>(buffer, start);

        if (!peek)
        {
            offset += length;
        }

        return result;
    }

    /**
     * Decodes a vector of values from the byte vector
     * @tparam T
     * @param peek
     * @return
     */
    template<typename T> std::vector<T> varintV(bool peek = false)
    {
        const auto start = offset;

        const auto count = varint<uint64_t>();

        std::vector<T> result;

        for (uint64_t i = 0; i < count; ++i)
        {
            const auto temp = varint<T>();

            result.push_back(temp);
        }

        if (peek)
        {
            offset = start;
        }

        return result;
    }

    /**
     * Returns the remaining number of bytes that have not been read from the byte vector
     * @return
     */
    [[nodiscard]] size_t unread_bytes() const
    {
        const auto unread = buffer.size() - offset;

        return (unread >= 0) ? unread : 0;
    }

    /**
     * Returns a byte vector copy of the remaining number of bytes that have not been read from the byte vector
     * @return
     */
    [[nodiscard]] std::vector<uint8_t> unread_data() const
    {
        return std::vector<uint8_t>(buffer.begin() + offset, buffer.end());
    }

  private:
    std::vector<uint8_t> buffer;

    size_t offset = 0;
};

/**
 * Serialization interface for inheritance
 */
struct ISerializable
{
    virtual void deserialize(deserializer_t &reader) = 0;

    virtual JSON_FROM_FUNC(fromJSON) = 0;

    virtual void serialize(serializer_t &writer) const = 0;

    [[nodiscard]] virtual std::vector<uint8_t> serialize() const = 0;

    [[nodiscard]] virtual size_t size() const = 0;

    virtual JSON_TO_FUNC(toJSON) = 0;

    [[nodiscard]] virtual std::string to_string() const = 0;
};

#endif // CRYPTO_SERIALIZER_H
