// Copyright (c) 2014-2020, The Bitcoin Core developers
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

#include "base58.h"

#include <cassert>

static const size_t BASE58_CHECKSUM_SIZE = 4;

static const char *Base58Characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t Base58Map[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,
    -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, -1, -1, -1, -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

namespace Crypto::Base58
{
    std::tuple<bool, std::vector<uint8_t>> decode(const std::string &input)
    {
        const auto *data = input.c_str();

        // skip and count leading 1s
        int zeroes = 0, length = 0;

        while (*data == '1')
        {
            zeroes++;

            *data++;
        }

        // allocate enough space in big-endian base256 representation
        int size = int(strlen(data)) * 733 / 1000 + 1; // log(58) / log(256) rounded up

        std::vector<unsigned char> b256(size);

        // process the characters
        static_assert(std::size(Base58Map) == 256, "Base58Map.size() should be 256");

        while (*data)
        {
            // decode base58 characters
            int carry = Base58Map[(uint8_t)*data];

            if (carry == -1)
            {
                return {false, {}};
            }

            int i = 0;

            for (auto it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i)
            {
                carry += 58 * (*it);

                *it = carry % 256;

                carry /= 256;
            }

            assert(carry == 0);

            length = i;

            data++;
        }

        if (*data != 0)
        {
            return {false, {}};
        }

        // skip leading zeroes in b256
        auto it = b256.begin() + (size - length);

        // copy the result into output vector
        std::vector<uint8_t> result;

        result.reserve(zeroes + (b256.end() - it));

        result.assign(zeroes, 0x00);

        while (it != b256.end())
        {
            result.push_back(*(it++));
        }

        return {true, result};
    }

    std::tuple<bool, std::vector<uint8_t>> decode_check(const std::string &input)
    {
        auto [success, decoded] = decode(input);

        if (!success)
        {
            return {false, {}};
        }

        if (decoded.size() <= BASE58_CHECKSUM_SIZE)
        {
            return {false, {}};
        }

        const auto checksum = std::vector<uint8_t>(decoded.end() - BASE58_CHECKSUM_SIZE, decoded.end());

        decoded.resize(decoded.size() - BASE58_CHECKSUM_SIZE);

        const auto expected_checksum = Crypto::Hashing::sha3(decoded.data(), decoded.size());

        // check the checksum
        if (std::memcmp(expected_checksum.data(), checksum.data(), BASE58_CHECKSUM_SIZE) != 0)
        {
            return {false, {}};
        }

        return {true, decoded};
    }

    std::string encode(std::vector<uint8_t> input)
    {
        // skip and count leading zeroes
        int zeroes = 0, length = 0;

        while (!input.empty() && input[0] == 0)
        {
            input = std::vector<uint8_t>(input.begin() + 1, input.end());

            zeroes++;
        }

        // allocate enough space in big-endian base58 representation
        int size = int(input.size()) * 138 / 100 + 1; // log(256) / log(58), rounded up

        std::vector<unsigned char> b58(size);

        // process the bytes
        while (!input.empty())
        {
            int carry = input[0];

            int i = 0;

            // apply "b58 = b58 * 256 + ch"
            for (auto it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++)
            {
                carry += 256 * (*it);

                *it = carry % 58;

                carry /= 58;
            }

            assert(carry == 0);

            length = i;

            input = std::vector<uint8_t>(input.begin() + 1, input.end());
        }

        // skip leading zeroes in base58 result
        auto it = b58.begin() + (size - length);

        while (it != b58.end() && *it == 0)
        {
            it++;
        }

        // translate the result into a string
        std::string result;

        result.reserve(zeroes + (b58.end() - it));

        result.assign(zeroes, '1');

        while (it != b58.end())
        {
            result += Base58Characters[*(it++)];
        }

        return result;
    }

    std::string encode_check(const std::vector<uint8_t> &input)
    {
        serializer_t writer;

        writer.bytes(input);

        const auto hash = Crypto::Hashing::sha3(writer.data(), writer.size());

        writer.bytes(hash.data(), BASE58_CHECKSUM_SIZE);

        return encode(writer.vector());
    }
} // namespace Crypto::Base58
