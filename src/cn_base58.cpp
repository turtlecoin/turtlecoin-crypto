// Copyright (c) 2011-2016, The Cryptonote Developers
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

#include "cn_base58.h"

#include "hashing.h"
#include "serializer.h"

#include <cassert>

#define SWAP64(x)                                                                             \
    ((((uint64_t)(x)&0x00000000000000ff) << 56) | (((uint64_t)(x)&0x000000000000ff00) << 40)  \
     | (((uint64_t)(x)&0x0000000000ff0000) << 24) | (((uint64_t)(x)&0x00000000ff000000) << 8) \
     | (((uint64_t)(x)&0x000000ff00000000) >> 8) | (((uint64_t)(x)&0x0000ff0000000000) >> 24) \
     | (((uint64_t)(x)&0x00ff000000000000) >> 40) | (((uint64_t)(x)&0xff00000000000000) >> 56))
#define IDENT64(x) ((uint64_t)(x))

#ifdef __BIG_ENDIAN__
#define SWAP64BE IDENT64
#else
#define SWAP64BE SWAP64
#endif

static inline uint64_t hi_dword(uint64_t val)
{
    return val >> 32;
}

static inline uint64_t lo_dword(uint64_t val)
{
    return val & 0xFFFFFFFF;
}

static inline uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi)
{
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = hi_dword(multiplier);

    uint64_t b = lo_dword(multiplier);

    uint64_t c = hi_dword(multiplicand);

    uint64_t d = lo_dword(multiplicand);

    uint64_t ac = a * c;

    uint64_t ad = a * d;

    uint64_t bc = b * c;

    uint64_t bd = b * d;

    uint64_t adbc = ad + bc;

    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);

    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;

    *product_hi = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    assert(ac <= *product_hi);

    return product_lo;
}

namespace Crypto::CNBase58
{
    const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    const size_t BASE58_ALPHABET_SIZE = sizeof(BASE58_ALPHABET) - 1;

    const size_t ENCODED_BLOCK_SIZES[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

    const size_t FULL_BLOCK_SIZE = sizeof(ENCODED_BLOCK_SIZES) / sizeof(ENCODED_BLOCK_SIZES[0]) - 1;

    const size_t FULL_ENCODED_BLOCK_SIZE = ENCODED_BLOCK_SIZES[FULL_BLOCK_SIZE];

    const size_t BASE58_CHECKSUM_SIZE = 4;

    struct cn_base58_reverse_alphabet
    {
        cn_base58_reverse_alphabet()
        {
            m_data.resize(BASE58_ALPHABET[BASE58_ALPHABET_SIZE - 1] - BASE58_ALPHABET[0] + 1, -1);

            for (size_t i = 0; i < BASE58_ALPHABET_SIZE; ++i)
            {
                auto idx = static_cast<size_t>(BASE58_ALPHABET[i] - BASE58_ALPHABET[0]);

                m_data[idx] = static_cast<int8_t>(i);
            }
        }

        int operator()(char letter) const
        {
            auto idx = static_cast<size_t>(letter - BASE58_ALPHABET[0]);

            return idx < m_data.size() ? m_data[idx] : -1;
        }

        static cn_base58_reverse_alphabet instance;

      private:
        std::vector<int8_t> m_data;
    };

    cn_base58_reverse_alphabet cn_base58_reverse_alphabet::instance;

    struct decoded_block_sizes
    {
        decoded_block_sizes()
        {
            m_data.resize(ENCODED_BLOCK_SIZES[FULL_BLOCK_SIZE] + 1, -1);

            for (size_t i = 0; i <= FULL_BLOCK_SIZE; ++i)
            {
                m_data[ENCODED_BLOCK_SIZES[i]] = static_cast<int>(i);
            }
        }

        int operator()(size_t encoded_block_size) const
        {
            assert(encoded_block_size <= FULL_ENCODED_BLOCK_SIZE);

            return m_data[encoded_block_size];
        }

        static decoded_block_sizes instance;

      private:
        std::vector<int> m_data;
    };

    decoded_block_sizes decoded_block_sizes::instance;

    static uint64_t uint_8be_to_64(const uint8_t *data, size_t size)
    {
        assert(1 <= size && size <= sizeof(uint64_t));

        uint64_t res = 0;

        switch (9 - size)
        {
            case 1:
                res |= *data++;
            case 2:
                res <<= 8;
                res |= *data++;
            case 3:
                res <<= 8;
                res |= *data++;
            case 4:
                res <<= 8;
                res |= *data++;
            case 5:
                res <<= 8;
                res |= *data++;
            case 6:
                res <<= 8;
                res |= *data++;
            case 7:
                res <<= 8;
                res |= *data++;
            case 8:
                res <<= 8;
                res |= *data;
                break;
            default:
                assert(false);
        }

        return res;
    }

    static void uint_64_to_8be(uint64_t num, size_t size, uint8_t *data)
    {
        assert(1 <= size && size <= sizeof(uint64_t));

        uint64_t num_be = SWAP64BE(num);

        memcpy(data, reinterpret_cast<uint8_t *>(&num_be) + sizeof(uint64_t) - size, size);
    }

    static void encode_block(const char *block, size_t size, char *res)
    {
        assert(1 <= size && size <= FULL_BLOCK_SIZE);

        uint64_t num = uint_8be_to_64(reinterpret_cast<const uint8_t *>(block), size);

        int i = static_cast<int>(ENCODED_BLOCK_SIZES[size]) - 1;

        while (0 < num)
        {
            uint64_t remainder = num % BASE58_ALPHABET_SIZE;

            num /= BASE58_ALPHABET_SIZE;

            res[i] = BASE58_ALPHABET[remainder];

            --i;
        }
    }

    static bool decode_block(const char *block, size_t size, char *res)
    {
        assert(1 <= size && size <= FULL_ENCODED_BLOCK_SIZE);

        int res_size = decoded_block_sizes::instance(size);

        if (res_size <= 0)
        {
            return false; // Invalid block size
        }

        uint64_t res_num = 0;

        uint64_t order = 1;

        for (size_t i = size - 1; i < size; --i)
        {
            int digit = cn_base58_reverse_alphabet::instance(block[i]);

            if (digit < 0)
            {
                return false; // Invalid symbol
            }

            uint64_t product_hi;

            uint64_t tmp = res_num + mul128(order, digit, &product_hi);

            if (tmp < res_num || 0 != product_hi)
            {
                return false; // Overflow
            }

            res_num = tmp;

            order *= BASE58_ALPHABET_SIZE; // Never overflows, 58^10 < 2^64
        }

        if (static_cast<size_t>(res_size) < FULL_BLOCK_SIZE && (UINT64_C(1) << (8 * res_size)) <= res_num)
        {
            return false; // Overflow
        }

        uint_64_to_8be(res_num, res_size, reinterpret_cast<uint8_t *>(res));

        return true;
    }

    std::tuple<bool, std::vector<uint8_t>> decode(const std::string &input)
    {
        if (input.empty())
        {
            return {false, {}};
        }

        size_t full_block_count = input.size() / FULL_ENCODED_BLOCK_SIZE;

        size_t last_block_size = input.size() % FULL_ENCODED_BLOCK_SIZE;

        int last_block_decoded_size = decoded_block_sizes::instance(last_block_size);

        if (last_block_decoded_size < 0)
        {
            return {false, {}}; // Invalid enc length
        }

        size_t data_size = full_block_count * FULL_BLOCK_SIZE + last_block_decoded_size;

        std::string data;

        data.resize(data_size, 0);

        for (size_t i = 0; i < full_block_count; ++i)
        {
            if (!decode_block(
                    input.data() + i * FULL_ENCODED_BLOCK_SIZE, FULL_ENCODED_BLOCK_SIZE, &data[i * FULL_BLOCK_SIZE]))
            {
                return {false, {}};
            }
        }

        if (0 < last_block_size)
        {
            if (!decode_block(
                    input.data() + full_block_count * FULL_ENCODED_BLOCK_SIZE,
                    last_block_size,
                    &data[full_block_count * FULL_BLOCK_SIZE]))
            {
                return {false, {}};
            }
        }

        return {true, Crypto::StringTools::from_hex(data)};
    }

    std::tuple<bool, std::vector<uint8_t>> decode_check(const std::string &input)
    {
        if (input.empty())
        {
            return {false, {}};
        }

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

    std::string encode(const std::vector<uint8_t> &input)
    {
        if (input.empty())
        {
            return std::string();
        }

        const auto data = Crypto::StringTools::to_hex(input.data(), input.size());

        size_t full_block_count = data.size() / FULL_BLOCK_SIZE;

        size_t last_block_size = data.size() % FULL_BLOCK_SIZE;

        size_t res_size = full_block_count * FULL_ENCODED_BLOCK_SIZE + ENCODED_BLOCK_SIZES[last_block_size];

        std::string res(res_size, BASE58_ALPHABET[0]);

        for (size_t i = 0; i < full_block_count; ++i)
        {
            encode_block(data.data() + i * FULL_BLOCK_SIZE, FULL_BLOCK_SIZE, &res[i * FULL_ENCODED_BLOCK_SIZE]);
        }

        if (0 < last_block_size)
        {
            encode_block(
                data.data() + full_block_count * FULL_BLOCK_SIZE,
                last_block_size,
                &res[full_block_count * FULL_ENCODED_BLOCK_SIZE]);
        }

        return res;
    }

    std::string encode_check(const std::vector<uint8_t> &input)
    {
        if (input.empty())
        {
            return std::string();
        }

        serializer_t writer;

        writer.bytes(input);

        const auto hash = Crypto::Hashing::sha3(writer.data(), writer.size());

        writer.bytes(hash.data(), BASE58_CHECKSUM_SIZE);

        return encode(writer.vector());
    }
} // namespace Crypto::CNBase58
