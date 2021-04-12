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

#ifndef CRYPTO_HASHING_H
#define CRYPTO_HASHING_H

#include "memory_helper.h"
#include "serializer.h"
#include "string_tools.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iterator>
#include <sha3.h>
#include <stdexcept>
#include <string>
#include <uint256_t.h>

extern "C"
{
#include <argon2.h>
};

/**
 * A structure representing a 256-bit hash value
 */
struct crypto_hash_t
{
    crypto_hash_t() {}

    crypto_hash_t(std::initializer_list<uint8_t> input)
    {
        std::copy(input.begin(), input.end(), std::begin(bytes));
    }

    crypto_hash_t(const uint8_t input[32])
    {
        std::copy(input, input + sizeof(bytes), std::begin(bytes));
    }

    crypto_hash_t(const std::vector<uint8_t> &input)
    {
        std::copy(input.begin(), input.end(), std::begin(bytes));
    }

    crypto_hash_t(const std::string &s)
    {
        from_string(s);
    }

    crypto_hash_t(const JSONValue &j)
    {
        if (!j.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());
    }

    crypto_hash_t(const JSONValue &j, const std::string &key)
    {
        const auto &val = get_json_value(j, key);

        if (!val.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());
    }

    ~crypto_hash_t()
    {
        secure_erase(&bytes, sizeof(bytes));
    }

    unsigned char &operator[](int i)
    {
        return bytes[i];
    }

    unsigned char operator[](int i) const
    {
        return bytes[i];
    }

    bool operator==(const crypto_hash_t &other) const
    {
        return std::equal(std::begin(bytes), std::end(bytes), std::begin(other.bytes));
    }

    bool operator!=(const crypto_hash_t &other) const
    {
        return !(*this == other);
    }

    bool operator<(const crypto_hash_t &other) const
    {
        for (size_t i = 32; i-- > 0;)
        {
            if (bytes[i] < other.bytes[i])
            {
                return true;
            }

            if (bytes[i] > other.bytes[i])
            {
                return false;
            }
        }

        return false;
    }

    bool operator>(const crypto_hash_t &other) const
    {
        for (size_t i = 32; i-- > 0;)
        {
            if (bytes[i] > other.bytes[i])
            {
                return true;
            }

            if (bytes[i] < other.bytes[i])
            {
                return false;
            }
        }

        return false;
    }

    /**
     * Returns a pointer to the underlying structure data
     * @return
     */
    [[nodiscard]] const uint8_t *data() const
    {
        return bytes;
    }

    /**
     * Returns if the structure is empty (unset)
     * @return
     */
    [[nodiscard]] bool empty() const
    {
        return *this == crypto_hash_t();
    }

    /**
     * Returns the number of leading 0s of the hash
     * @param reversed
     * @return
     */
    [[nodiscard]] size_t leading_zeros(bool reversed = true) const
    {
        size_t count = 0;

        const auto bits = to_bits(reversed);

        for (const auto &bit : bits)
        {
            if (bit != 0)
            {
                break;
            }

            count++;
        }

        return count;
    }

    /**
     * Serializes the struct to a byte array
     * @param writer
     */
    void serialize(serializer_t &writer) const
    {
        writer.bytes(&bytes, sizeof(bytes));
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
     * Use this method instead of sizeof(Hash) to get the resulting
     * size of the key in bytes
     * @return
     */
    [[nodiscard]] size_t size() const
    {
        return sizeof(bytes);
    }

    /**
     * Generates a vector of the individual bits within the hash without regard to the
     * endianness of the value by using the individual bytes represented in the hash
     * @param reversed
     * @return
     */
    [[nodiscard]] std::vector<uint8_t> to_bits(bool reversed = false) const
    {
        const auto bits = sizeof(bytes) * 8;

        std::vector<uint8_t> result, temp;

        result.reserve(bits);

        for (const auto &byte : bytes)
        {
            temp.clear();

            for (size_t j = 0; j < 8; ++j)
            {
                const uint8_t bit((byte >> j) & 0x01);

                temp.push_back(bit);
            }

            std::reverse(temp.begin(), temp.end());

            for (const auto &bit : temp)
            {
                result.push_back(bit);
            }
        }

        if (reversed)
        {
            std::reverse(result.begin(), result.end());
        }

        return result;
    }

    /**
     * Converts the structure to a JSON object
     * @param writer
     */
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
    {
        writer.String(to_string());
    }

    /**
     * Encodes a hash as a hexadecimal string
     * @return
     */
    [[nodiscard]] std::string to_string() const
    {
        return Crypto::StringTools::to_hex(bytes, sizeof(bytes));
    }

    /**
     * Returns the hash as an uint256_t
     * @return
     */
    [[nodiscard]] uint256_t to_uint256_t() const
    {
        /**
         * uint256_t presumes that we are always working in big-endian when loading from
         * hexadecimal; however, the vast majority of our work in hex is little-endian
         * and as a result, we need to reverse the order of the array to arrive at the
         * correct value being stored in the uint256_t
         */

        uint8_t temp[32] = {0};

        std::memcpy(temp, bytes, sizeof(bytes));

        std::reverse(std::begin(temp), std::end(temp));

        const auto hex = Crypto::StringTools::to_hex(temp, sizeof(temp));

        uint256_t result(hex, 16);

        return result;
    }

    uint8_t bytes[32] = {0};

  private:
    void from_string(const std::string &s)
    {
        const auto input = Crypto::StringTools::from_hex(s);

        if (input.size() < size())
        {
            throw std::runtime_error("Could not load scalar");
        }

        std::copy(input.begin(), input.end(), std::begin(bytes));
    }
};

typedef crypto_hash_t crypto_seed_t;

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_hash_t &value)
    {
        os << value.to_string();

        return os;
    }
} // namespace std

namespace Crypto::Hashing
{
    namespace Merkle
    {
        /**
         * Generates the merkle tree branches for the given set of hashes
         * @param hashes
         */
        std::vector<crypto_hash_t> tree_branch(const std::vector<crypto_hash_t> &hashes);

        /**
         * Calculates the depth of the merkle tree based on the count of elements
         * @param count
         * @return
         */
        size_t tree_depth(size_t count);

        /**
         * Generates the merkle root hash for the given set of hashes
         * @param hashes
         * @param root_hash
         */
        crypto_hash_t root_hash(const std::vector<crypto_hash_t> &hashes);

        /**
         * Generates the merkle root hash from the given set of merkle branches and the supplied leaf
         * following the provided path (0 or 1)
         * @param branches
         * @param depth
         * @param leaf
         * @param root_hash
         * @param path
         */
        crypto_hash_t root_hash_from_branch(
            const std::vector<crypto_hash_t> &branches,
            size_t depth,
            const crypto_hash_t &leaf,
            const uint8_t &path = 0);
    } // namespace Merkle

    /**
     * Hashes the given data with the given salt using Argon2d into a 256-bit hash
     * @param input
     * @param length
     * @param salt
     * @param salt_length
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    crypto_hash_t argon2d(
        const void *input,
        size_t length,
        const void *salt,
        size_t salt_length,
        size_t iterations = 1,
        size_t memory = 256,
        size_t threads = 1);

    /**
     * Hashes the given vector of data (using itself as salt) using Argon2d into a 256-bit hash
     * @tparam T
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    template<typename T>
    crypto_hash_t argon2d(
        const std::vector<T> &input,
        const size_t iterations = 1,
        const size_t memory = 256,
        const size_t threads = 1)
    {
        return argon2d(input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data (using itself as salt) using Argon2d into a 256-bit hash
     * @tparam T
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    template<typename T>
    crypto_hash_t
        argon2d(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return argon2d(input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data with the given salt using Argon2d into a 256-bit hash
     * @param input
     * @param length
     * @param salt
     * @param salt_length
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    crypto_hash_t argon2i(
        const void *input,
        size_t length,
        const void *salt,
        size_t salt_length,
        size_t iterations = 1,
        size_t memory = 256,
        size_t threads = 1);

    /**
     * Hashes the given vector of data (using itself as salt) using Argon2i into a 256-bit hash
     * @tparam T
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    template<typename T>
    crypto_hash_t argon2i(
        const std::vector<T> &input,
        const size_t iterations = 1,
        const size_t memory = 256,
        const size_t threads = 1)
    {
        return argon2i(input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data (using itself as salt) using Argon2i into a 256-bit
     * @tparam T
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    template<typename T>
    crypto_hash_t
        argon2i(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return argon2i(input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data with the given salt using Argon2d into a 256-bit hash
     * @param input
     * @param length
     * @param salt
     * @param salt_length
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    crypto_hash_t argon2id(
        const void *input,
        size_t length,
        const void *salt,
        size_t salt_length,
        size_t iterations = 1,
        size_t memory = 256,
        size_t threads = 1);

    /**
     * Hashes the given vector of data (using itself as salt) using Argon2id into a 256-bit hash
     * @tparam T
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    template<typename T>
    crypto_hash_t argon2id(
        const std::vector<T> &input,
        const size_t iterations = 1,
        const size_t memory = 256,
        const size_t threads = 1)
    {
        return argon2id(input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data (using itself as salt) using Argon2id into a 256-bit
     * @tparam T
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     * @return
     */
    template<typename T>
    crypto_hash_t
        argon2id(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return argon2id(input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given input data using SHA-3 into a 256-bit hash
     * @param input
     * @param length
     * @return
     */
    crypto_hash_t sha3(const void *input, size_t length);

    /**
     * Hashes the given vector of data using SHA-3 into a 256-bit hash
     * @param input
     * @return
     */
    template<typename T> crypto_hash_t sha3(const std::vector<T> &input)
    {
        return sha3(input.data(), input.size() * sizeof(T));
    }

    /**
     * Hashes the given input data using SHA-3 into a 256-bit hash
     * @param input
     * @return
     */
    template<typename T> crypto_hash_t sha3(const T &input)
    {
        return sha3(input.data(), input.size());
    }

    /**
     * Hashes the given input using SHA-3 for the number of rounds indicated by iterations
     * this method also performs basic key stretching whereby the input data is appended
     * to the resulting hash each round to "salt" each round of hashing to prevent simply
     * iterating the hash over itself
     * @param input
     * @param length
     * @param iterations
     * @return
     */
    crypto_hash_t sha3_slow_hash(const void *input, size_t length, uint64_t iterations);

    /**
     * Hashes the given POD using SHA-3 for the number of rounds indicated by iterations
     * this method also performs basic key stretching whereby the input data is appended
     * to the resulting hash each round to "salt" each round of hashing to prevent simply
     * iterating the hash over itself
     * @param input
     * @param iterations
     * @return
     */
    template<typename T> crypto_hash_t sha3_slow_hash(const T &input, uint64_t iterations = 0)
    {
        return sha3_slow_hash(input.data(), input.size(), iterations);
    }
} // namespace Crypto::Hashing

#endif // CRYPTO_HASHING_H
