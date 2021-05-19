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

#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H

#include "memory_helper.h"
#include "serializer.h"
#include "string_tools.h"

#include <cstring>
#include <ed25519.h>
#include <stdexcept>
#include <uint128_t.h>
#include <uint256_t.h>

#define SCALAR_OR_THROW(value) \
    if (!value.check())        \
    throw std::invalid_argument(std::string(#value) + " is not a scalar")

/**
 * l = 2^252 + 2774231777737235353585193779
 */
static const uint8_t l[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                              0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/**
 * Scalar inversion exponent
 * linv = l - 2
 */
static const uint8_t l_inversion_exponent[32] = {0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                                 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/**
 * q = 2^255 - 19
 * Value is provided here for reference purposes
 */
static const uint8_t q[32] = {0xeD, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

struct crypto_point_t
{
    /**
     * Various constructor methods for creating a point. All of the methods
     * will load the various types, then automatically load the related
     * ge_p2 and ge_p2 points into cached memory to help speed up operations
     * that use them later without incurring the cost of loading them from bytes
     * again. While this uses a bit more memory to represent a point, it does
     * provide us with a more performant experience when conducting arithmetic
     * operations using the point
     */

    crypto_point_t()
    {
        ge_frombytes_negate_vartime(&point3, bytes);
    }

    crypto_point_t(std::initializer_list<uint8_t> input)
    {
        std::copy(input.begin(), input.end(), std::begin(bytes));

        if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
        {
            throw std::runtime_error("could not load point");
        }

        ge_p3_to_cached(&cached_point, &point3);
    }

    crypto_point_t(const uint8_t input[32])
    {
        std::copy(input, input + sizeof(bytes), std::begin(bytes));

        if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
        {
            throw std::runtime_error("could not load point");
        }

        ge_p3_to_cached(&cached_point, &point3);
    }

    crypto_point_t(const uint64_t &number)
    {
        std::memcpy(bytes, &number, sizeof(number));

        if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
        {
            throw std::runtime_error("could not load point");
        }

        ge_p3_to_cached(&cached_point, &point3);
    }

    crypto_point_t(const uint256_t &number)
    {
        std::memcpy(bytes, &number, sizeof(number));

        if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
        {
            throw std::runtime_error("could not load point");
        }

        ge_p3_to_cached(&cached_point, &point3);
    }

    crypto_point_t(const std::vector<uint8_t> &input)
    {
        if (input.size() < size())
        {
            throw std::runtime_error("could not load point");
        }

        std::copy(input.begin(), input.end(), std::begin(bytes));

        if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
        {
            throw std::runtime_error("could not load point");
        }

        ge_p3_to_cached(&cached_point, &point3);
    }

    crypto_point_t(const ge_p3 &point): point3(point)
    {
        ge_p3_tobytes(bytes, &point);

        ge_p3_to_cached(&cached_point, &point3);
    }

    crypto_point_t(const std::string &s)
    {
        from_string(s);
    }

    crypto_point_t(const JSONValue &j)
    {
        if (!j.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());
    }

    crypto_point_t(const JSONValue &j, const std::string &key)
    {
        const auto &val = get_json_value(j, key);

        if (!val.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());
    }

    ~crypto_point_t()
    {
        secure_erase(&bytes, sizeof(bytes));

        secure_erase(&point3, sizeof(point3));

        secure_erase(&cached_point, sizeof(cached_point));
    }

    /**
     * Allows us to check a random value to determine if it is a scalar or not
     * @param value
     * @return
     */
    template<typename T> static bool check(const T &value)
    {
        /**
         * Try loading the given value into a point type and then check to see if the bytes
         * that we have loaded are actually a point. If we fail at any point, then it
         * definitely is not a point that was provided.
         */
        try
        {
            crypto_point_t check_value(value);

            return check_value.check();
        }
        catch (...)
        {
            return false;
        }
    }

    /**
     * Overloading a bunch of the standard operators to make operations using this
     * structure to use a lot cleaner syntactic sugar in downstream code.
     */

    unsigned char operator[](int i) const
    {
        return bytes[i];
    }

    bool operator==(const crypto_point_t &other) const
    {
        return std::equal(std::begin(bytes), std::end(bytes), std::begin(other.bytes));
    }

    bool operator!=(const crypto_point_t &other) const
    {
        return !(*this == other);
    }

    bool operator<(const crypto_point_t &other) const
    {
        for (size_t i = 32; i-- > 0;)
        {
            if (bytes[i] < other.bytes[i])
            {
                return true;
            }
            else if (bytes[i] > other.bytes[i])
            {
                return false;
            }
        }

        return false;
    }

    bool operator<=(const crypto_point_t &other) const
    {
        return (*this == other) || (*this < other);
    }

    bool operator>(const crypto_point_t &other) const
    {
        for (size_t i = 32; i-- > 0;)
        {
            if (bytes[i] > other.bytes[i])
            {
                return true;
            }
            else if (bytes[i] < other.bytes[i])
            {
                return false;
            }
        }

        return false;
    }

    bool operator>=(const crypto_point_t &other) const
    {
        return (*this == other) || (*this > other);
    }

    crypto_point_t operator+(const crypto_point_t &other) const
    {
        ge_p1p1 tmp2;

        // AB = (a + b) mod l
        ge_add(&tmp2, &point3, &other.cached_point);

        ge_p3 final;

        ge_p1p1_to_p3(&final, &tmp2);

        return crypto_point_t(final);
    }

    void operator+=(const crypto_point_t &other)
    {
        *this = *this + other;
    }

    crypto_point_t operator-(const crypto_point_t &other) const
    {
        ge_p1p1 tmp2;

        // AB = (a - b) mod l
        ge_sub(&tmp2, &point3, &other.cached_point);

        ge_p3 final;

        ge_p1p1_to_p3(&final, &tmp2);

        return crypto_point_t(final);
    }

    crypto_point_t operator-() const
    {
        crypto_point_t other({1}); // Z = (0, 1)

        return other - *this;
    }

    void operator-=(const crypto_point_t &other)
    {
        *this = *this - other;
    }

    /**
     * Member methods used in general operations using scalars
     */

    /**
     * Returns a pointer to a ge_cached representation of the point
     * @return
     */
    [[nodiscard]] ge_cached cached() const
    {
        return cached_point;
    }

    /**
     * Checks to confirm that the point is indeed a point
     * @return
     */
    [[nodiscard]] bool check() const
    {
        ge_p3 tmp;

        return ge_frombytes_negate_vartime(&tmp, bytes) == 0;
    }

    /**
     * Checks to confirm that the point is in our subgroup
     * @return
     */
    [[nodiscard]] bool check_subgroup() const
    {
        ge_dsmp tmp;

        ge_dsm_precomp(tmp, &point3);

        return ge_check_subgroup_precomp_negate_vartime(tmp) == 0;
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
        return *this == crypto_point_t();
    }

    /**
     * Computes 8P
     * @return
     */
    [[nodiscard]] crypto_point_t mul8() const
    {
        ge_p1p1 tmp;

        ge_p2 point2;

        ge_p3_to_p2(&point2, &point3);

        ge_mul8(&tmp, &point2);

        ge_p3 tmp2;

        ge_p1p1_to_p3(&tmp2, &tmp);

        return crypto_point_t(tmp2);
    }

    /**
     * Returns the negation of the point
     * @return
     */
    [[nodiscard]] crypto_point_t negate() const
    {
        crypto_point_t Z({0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        return Z - *this;
    }

    /**
     * Returns a pointer to a ge_p3 representation of the point
     * @return
     */
    [[nodiscard]] ge_p3 p3() const
    {
        return point3;
    }

    /**
     * Reduces the given bytes, whether a point on the curve or not, to a point
     * @param bytes
     * @return
     */
    [[nodiscard]] static crypto_point_t reduce(const uint8_t bytes[32])
    {
        ge_p2 point;

        ge_p1p1 point2;

        ge_p3 point3;

        ge_fromfe_frombytes_negate_vartime(&point, bytes);

        ge_mul8(&point2, &point);

        ge_p1p1_to_p3(&point3, &point2);

        return crypto_point_t(point3);
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
     * Use this method instead of sizeof(crypto_point_t) to get the resulting
     * size of the key in bytes
     * @return
     */
    [[nodiscard]] size_t size() const
    {
        return sizeof(bytes);
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
     * Encodes the point as a hexadecimal string
     * @return
     */
    [[nodiscard]] std::string to_string() const
    {
        return Crypto::StringTools::to_hex(bytes, sizeof(bytes));
    }

    /**
     * Returns the point as an uint256_t
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

  private:
    /**
     * Loads the point from a hexademical string
     * @param s
     */
    void from_string(const std::string &s)
    {
        const auto input = Crypto::StringTools::from_hex(s);

        if (input.size() < size())
        {
            throw std::runtime_error("could not load point");
        }

        std::copy(input.begin(), input.end(), std::begin(bytes));

        if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
        {
            throw std::runtime_error("could not load point");
        }

        ge_p3_to_cached(&cached_point, &point3);
    }

    uint8_t bytes[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ge_p3 point3;
    ge_cached cached_point;
};

namespace Crypto
{
    // Primary Generator Point (x,-4/5)
    const crypto_point_t G = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

    // Secondary Generator Point = Hp(G)
    const crypto_point_t H = {0xdd, 0x2a, 0xf5, 0xc2, 0x8a, 0xcc, 0xdc, 0x50, 0xc8, 0xbc, 0x4e,
                              0x15, 0x99, 0x12, 0x82, 0x3a, 0x87, 0x87, 0xc1, 0x18, 0x52, 0x97,
                              0x74, 0x5f, 0xb2, 0x30, 0xe2, 0x64, 0x6c, 0xd7, 0x7e, 0xf6};

    const crypto_point_t U = {0x3b, 0x51, 0x37, 0xf1, 0x67, 0x4c, 0x55, 0xf9, 0xad, 0x2b, 0x5d,
                              0xbf, 0x14, 0x99, 0x69, 0xc5, 0x62, 0x4a, 0x84, 0x36, 0xbc, 0xfb,
                              0x99, 0xc6, 0xac, 0x30, 0x1b, 0x4b, 0x31, 0x21, 0x93, 0xf2};

    // Zero Point (0,0)
    const crypto_point_t ZP = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Neutral Point (0,1)
    const crypto_point_t Z = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
} // namespace Crypto

struct crypto_scalar_t
{
    /**
     * Constructor methods
     */

    crypto_scalar_t() {}

    crypto_scalar_t(std::initializer_list<uint8_t> input, bool reduce = false)
    {
        std::copy(input.begin(), input.end(), std::begin(bytes));

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const uint8_t input[32], bool reduce = false)
    {
        std::copy(input, input + sizeof(bytes), std::begin(bytes));

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const std::string &s, bool reduce = false)
    {
        from_string(s);

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const uint64_t &number, bool reduce = false)
    {
        std::memcpy(bytes, &number, sizeof(number));

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const uint256_t &number, bool reduce = false)
    {
        std::memcpy(bytes, &number, sizeof(number));

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const std::vector<uint8_t> &input, bool reduce = false)
    {
        /**
         * We allow loading a full scalar (256-bits), a uint64_t (64-bits), or a uint32_t (32-bits)
         */
        if (input.size() < size() && input.size() != 8 && input.size() != 4)
        {
            throw std::runtime_error("Could not load scalar");
        }

        std::copy(input.begin(), input.end(), std::begin(bytes));

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const std::vector<crypto_scalar_t> &bits, bool reduce = false)
    {
        from_bits(bits);

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const JSONValue &j, bool reduce = false)
    {
        if (!j.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());

        if (reduce)
        {
            do_reduce();
        }
    }

    crypto_scalar_t(const JSONValue &j, const std::string &key, bool reduce = false)
    {
        const auto &val = get_json_value(j, key);

        if (!val.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());

        if (reduce)
        {
            do_reduce();
        }
    }

    ~crypto_scalar_t()
    {
        secure_erase(&bytes, sizeof(bytes));
    }

    /**
     * Operator overloads to make arithmetic a lot easier to handle in methods that use these structures
     */

    unsigned char &operator[](int i)
    {
        return bytes[i];
    }

    unsigned char operator[](int i) const
    {
        return bytes[i];
    }

    bool operator==(const crypto_scalar_t &other) const
    {
        return std::equal(std::begin(bytes), std::end(bytes), std::begin(other.bytes));
    }

    bool operator!=(const crypto_scalar_t &other) const
    {
        return !(*this == other);
    }

    bool operator<(const crypto_scalar_t &other) const
    {
        for (size_t i = 32; i-- > 0;)
        {
            if (bytes[i] < other.bytes[i])
            {
                return true;
            }
            else if (bytes[i] > other.bytes[i])
            {
                return false;
            }
        }

        return false;
    }

    bool operator<=(const crypto_scalar_t &other) const
    {
        return (*this < other) || (*this == other);
    }

    bool operator>(const crypto_scalar_t &other) const
    {
        for (size_t i = 32; i-- > 0;)
        {
            if (bytes[i] > other.bytes[i])
            {
                return true;
            }
            else if (bytes[i] < other.bytes[i])
            {
                return false;
            }
        }

        return false;
    }

    bool operator>=(const crypto_scalar_t &other) const
    {
        return (*this > other) || (*this == other);
    }

    crypto_scalar_t operator+(const crypto_scalar_t &other) const
    {
        crypto_scalar_t result;

        sc_add(result.bytes, bytes, other.bytes);

        return result;
    }

    void operator+=(const crypto_scalar_t &other)
    {
        sc_add(bytes, bytes, other.bytes);
    }

    crypto_scalar_t operator-(const crypto_scalar_t &other) const
    {
        crypto_scalar_t result;

        sc_sub(result.bytes, bytes, other.bytes);

        return result;
    }

    void operator-=(const crypto_scalar_t &other)
    {
        sc_sub(bytes, bytes, other.bytes);
    }

    crypto_scalar_t operator*(const crypto_scalar_t &other) const
    {
        crypto_scalar_t result;

        sc_mul(result.bytes, bytes, other.bytes);

        return result;
    }

    /**
     * Overloads a Scalar * Point returning the resulting point
     * @param point
     * @return
     */
    crypto_point_t operator*(const crypto_point_t &point) const
    {
        ge_p3 temp_p3;

        ge_p1p1 temp_p1p1;

        if (point == Crypto::G) // If we're multiplying by G, use the base method, it's faster
        {
            ge_scalarmult_base(&temp_p1p1, bytes);

            ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

            return crypto_point_t(temp_p3);
        }
        else
        {
            const auto p = point.p3();

            // aB = (a * B) mod l
            ge_scalarmult(&temp_p1p1, bytes, &p);

            ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

            return crypto_point_t(temp_p3);
        }
    }

    void operator*=(const crypto_scalar_t &other)
    {
        sc_mul(bytes, bytes, other.bytes);
    }

    /**
     * Performs a double scalar mult operation which is slightly faster than
     * two single scalarmult operations added together
     * @param A
     * @param b
     * @param B
     * @return
     */
    [[nodiscard]] crypto_point_t
        dbl_mult(const crypto_point_t &A, const crypto_scalar_t &b, const crypto_point_t &B) const
    {
        ge_p1p1 temp_p1p1;

        ge_p3 temp_p3;

        if (B == Crypto::G)
        {
            temp_p3 = A.p3();

            ge_double_scalarmult_base_negate_vartime(&temp_p1p1, bytes, &temp_p3, b.data());
        }
        else
        {
            temp_p3 = B.p3();

            ge_dsmp temp_precomp;

            ge_dsm_precomp(temp_precomp, &temp_p3);

            temp_p3 = A.p3();

            ge_double_scalarmult_negate_vartime(&temp_p1p1, bytes, &temp_p3, b.data(), temp_precomp);
        }

        ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

        crypto_point_t point(temp_p3);

        return point != Crypto::ZP ? point : Crypto::Z;
    }

    /**
     * Allows us to check a random value to determine if it is a scalar or not
     * @param value
     * @return
     */
    template<typename T> static bool check(const T &value)
    {
        /**
         * Try loading the given value into a scalar type without performing a scalar reduction
         * (which would defeat the purpose of this check) and then check to see if the bytes
         * that we have loaded indicate that the value is actually a scalar. If we fail
         * at any point, then it definitely is not a scalar that was provided.
         */
        try
        {
            crypto_scalar_t check_value(value, false);

            return check_value.check();
        }
        catch (...)
        {
            return false;
        }
    }

    /**
     * Member methods used in general operations using scalars
     */

    /**
     * Checks to validate that the scalar is indeed a scalar
     * @return
     */
    [[nodiscard]] bool check() const
    {
        return sc_check(bytes) == 0;
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
        return *this == crypto_scalar_t();
    }

    /**
     * Provides the inversion of the scalar (1/x)
     * @return
     */
    [[nodiscard]] crypto_scalar_t invert() const
    {
        return pow(l_inversion_exponent);
    }

    /**
     * Checks to validate that the scalar is NOT zero (0)
     * @return
     */
    [[nodiscard]] bool is_nonzero() const
    {
        return sc_isnonzero(bytes) == 0;
    }

    /**
     * Returns the negation of the scalar (-x)
     * @return
     */
    [[nodiscard]] crypto_scalar_t negate() const
    {
        crypto_scalar_t zero({0});

        return zero - *this;
    }

    /**
     * Raises the scalar to the specified power
     * r = (s ^ e)
     * @param exponent
     * @return
     */
    [[nodiscard]] crypto_scalar_t pow(const crypto_scalar_t &exponent) const
    {
        // convert our exponent to a vector of 256 individual bits
        const auto bits = exponent.to_bits(256);

        crypto_scalar_t result(1), m(bytes);

        size_t upper_bound = 0;

        /**
         * Locate the highest set bit to limit the range of our loop
         * thus reducing the number of scalar multiplications performed
         */
        for (size_t i = 0; i < bits.size(); ++i)
        {
            if (bits[i][0] == 1)
            {
                upper_bound = i;
            }
        }

        /**
         * Use the double-and-multiply method to calculate the value which results in us
         * performing at maximum, 512 scalar multiplication operations.
         */
        for (size_t i = 0; i <= upper_bound; ++i)
        {
            if (bits[i] == 1)
            {
                result *= m;
            }

            m *= m;
        }

        return result;
    }

    /**
     * Raises the scalar to the specified power with a modulus
     * r = (s ^ e) % m
     * @param exponent
     * @param modulus
     * @return
     */
    [[nodiscard]] crypto_scalar_t powm(const crypto_scalar_t &exponent, size_t modulus) const
    {
        return crypto_scalar_t(pow(exponent).to_uint256_t() % modulus);
    }

    /**
     * Generates a vector of powers of the scalar
     * @param count
     * @param descending
     * @return
     */
    [[nodiscard]] std::vector<crypto_scalar_t>
        pow_expand(size_t count, bool descending = false, bool include_zero = true) const
    {
        if (count == 0)
        {
            throw std::invalid_argument("count should be non-zero");
        }

        std::vector<crypto_scalar_t> result(count);

        size_t start = 0, end = count;

        if (!include_zero)
        {
            start += 1;

            end += 1;
        }

        for (size_t i = start, j = 0; i < end; ++i, ++j)
        {
            result[j] = pow(i);
        }

        if (descending)
        {
            std::reverse(result.begin(), result.end());
        }

        return result;
    }

    /**
     * Sums the specified power of the scalar
     * @param count
     * @return
     */
    [[nodiscard]] crypto_scalar_t pow_sum(size_t count) const
    {
        const bool is_power_of_2 = (count & (count - 1)) == 0;

        if (!is_power_of_2)
        {
            throw std::runtime_error("must be a power of 2");
        }

        if (count == 0)
        {
            return {0};
        }

        if (count == 1)
        {
            return 1;
        }

        crypto_scalar_t result(1), base(bytes);

        result += base;

        while (count > 2)
        {
            base *= base;

            result += result * base;

            count /= 2;
        }

        return result;
    }

    /**
     * Returns the reduced form of the scalar (if not already reduced)
     */
    [[nodiscard]] crypto_scalar_t reduce() const
    {
        uint8_t temp[32] = {0};

        std::memcpy(&temp, bytes, sizeof(bytes));

        sc_reduce32(temp);

        return temp;
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
     * Use this method instead of sizeof(crypto_scalar_t) to get the resulting
     * size of the key in bytes -- this is provided here just to help match up the
     * two structure types (point & scalar)
     * @return
     */
    [[nodiscard]] size_t size() const
    {
        return sizeof(bytes);
    }

    /**
     * Squares the scalar
     * r = (s ^ 2)
     * @return
     */
    [[nodiscard]] crypto_scalar_t squared() const
    {
        crypto_scalar_t result;

        sc_mul(result.bytes, bytes, bytes);

        return result;
    }

    /**
     * Converts the scalar to a vector of scalars that represent the individual
     * bits of the scalar (maximum of 256 bits as 32 * 8 = 256)
     * @param bits
     * @return
     */
    [[nodiscard]] std::vector<crypto_scalar_t> to_bits(size_t bits = 256) const
    {
        if (bits > 256)
        {
            throw std::range_error("requested bit length exceeds maximum scalar bit length");
        }

        std::vector<crypto_scalar_t> result;

        result.reserve(bits);

        size_t offset = 0;

        uint64_t temp;

        // Loop until we have the number of requested bits
        while (result.size() != bits)
        {
            /**
             * Load the first 8-bytes (64 bits) into a uint64_t to make it easier
             * to manipulate using standard bit shifts
             */
            std::memcpy(&temp, std::begin(bytes) + offset, 8);

            // Loop through the 64-bits in the uint64_t
            for (size_t i = 0; i < 64; i++)
            {
                // Once we have the requested number of bits, break the loop
                if (result.size() == bits)
                {
                    break;
                }

                const crypto_scalar_t bit((temp >> i) & 0x01);

                result.push_back(bit);
            }

            // Adjust the offset in the event we need more than 64-bits from the scalar
            offset += sizeof(temp);
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
     * Encodes the specified number of bytes of the scalar as a hexadecimal string
     * @param byte_length
     * @return
     */
    [[nodiscard]] std::string to_string(size_t byte_length = 32) const
    {
        if (byte_length > 32)
        {
            throw std::range_error("length cannot exceed the size of the scalar");
        }

        return Crypto::StringTools::to_hex(bytes, byte_length);
    }

    /**
     * Encodes the first 8 bytes of the scalar as a uint64_t
     * @return
     */
    [[nodiscard]] uint64_t to_uint64_t() const
    {
        uint64_t result;

        std::memcpy(&result, &bytes, sizeof(result));

        return result;
    }

    /**
     * Returns the scalar as an uint256_t
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

  private:
    uint8_t bytes[32] = {0};

    /**
     * Reduces the bytes in the scalar such that it is, most definitely, a scalar
     */
    void do_reduce()
    {
        sc_reduce32(bytes);
    }

    /**
     * Loads the scalar from a vector of individual bits
     * @param bits
     */
    void from_bits(const std::vector<crypto_scalar_t> &bits)
    {
        constexpr size_t bits_mod = 32;

        // set all bytes to zero
        std::fill(std::begin(bytes), std::end(bytes), 0);

        if (bits.empty())
        {
            return;
        }

        const crypto_scalar_t ZERO = {0}, ONE = 1;

        size_t offset = 0;

        uint32_t tmp = 0;

        // loop through the individual bits
        for (size_t i = 0; i < bits.size(); ++i)
        {
            if (bits[i] != ZERO && bits[i] != ONE)
            {
                throw std::range_error("individual bit scalar values must be zero (0) or one (1)");
            }

            /**
             * If we are not at the start of the bits supplied and we have consumed
             * enough bits to complete a uint32_t, then move it on to the byte stack
             */
            if (i != 0 && i % bits_mod == 0)
            {
                // move the current uint32_t into the bytes
                std::memcpy(bytes + offset, &tmp, sizeof(tmp));

                // reset the uint32_t
                tmp = 0;

                // increment the offset by the size of the uint32_t
                offset += sizeof(tmp);
            }

            // if the bit is one (1) then we need to shift it into place
            if (bits[i] == 1)
            {
                tmp |= 1 << (i % bits_mod);
            }
        }

        // move the current uint32_t into the bytes at the current offset
        std::memcpy(bytes + offset, &tmp, sizeof(tmp));
    }

    /**
     * Loads the scalar from a hexadecimal encoded string
     * @param s
     */
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

namespace Crypto
{
    // Commonly used Scalar values (0, 1, 2, 8, 1/8)
    const crypto_scalar_t ZERO = {0}, ONE(1), TWO(2), EIGHT(8), INV_EIGHT = EIGHT.invert();

    const crypto_scalar_t L = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                               0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
} // namespace Crypto

/**
 * Converts an crypto_point_t to an crypto_scalar_t
 * @param point
 * @return
 */
static inline crypto_scalar_t pointToScalar(const crypto_point_t &point)
{
    uint8_t bytes[32];

    std::memcpy(&bytes, point.data(), sizeof(bytes));

    return crypto_scalar_t(bytes);
}

#define PointToScalar(a) pointToScalar(a)

/**
 * These are aliased here to make it clearer what context the point and scalars are
 * being used for during different method calls. This helps to avoid confusion
 * when working with the various method calls without losing track of the type
 * of the parameters being passed and their return values
 */

typedef crypto_point_t crypto_public_key_t;

typedef crypto_scalar_t crypto_secret_key_t;

typedef crypto_point_t crypto_derivation_t;

typedef crypto_point_t crypto_key_image_t;

typedef crypto_scalar_t crypto_blinding_factor_t;

typedef crypto_point_t crypto_pedersen_commitment_t;

struct crypto_signature_t
{
    /**
     * Constructor methods
     */

    crypto_signature_t() {}

    crypto_signature_t(std::initializer_list<uint8_t> LR)
    {
        std::copy(LR.begin(), LR.end(), std::begin(bytes));
    }

    crypto_signature_t(const std::vector<uint8_t> &LR)
    {
        if (LR.size() < size())
        {
            throw std::runtime_error("could not load signature");
        }

        std::copy(LR.begin(), LR.end(), std::begin(bytes));
    }

    crypto_signature_t(const uint8_t LR[64])
    {
        std::copy(LR, LR + sizeof(bytes), std::begin(bytes));
    }

    crypto_signature_t(const uint8_t L[32], const uint8_t R[32])
    {
        LR.L = L;

        LR.R = R;
    }

    crypto_signature_t(const std::string &LR)
    {
        from_string(LR);
    }

    crypto_signature_t(const JSONValue &j)
    {
        if (!j.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());
    }

    crypto_signature_t(const JSONValue &j, const std::string &key)
    {
        const auto &val = get_json_value(j, key);

        if (!val.IsString())
        {
            throw std::invalid_argument("JSON value is of the wrong type");
        }

        from_string(j.GetString());
    }

    ~crypto_signature_t()
    {
        secure_erase(&bytes, sizeof(bytes));
    }

    /**
     * Simple operator overloads for comparison
     */

    unsigned char operator[](int i) const
    {
        return bytes[i];
    }

    bool operator==(const crypto_signature_t &other) const
    {
        return std::equal(std::begin(bytes), std::end(bytes), std::begin(other.bytes));
    }

    bool operator!=(const crypto_signature_t &other) const
    {
        return !(*this == other);
    }

    /**
     * Returns if the structure is empty (unset)
     * @return
     */
    [[nodiscard]] bool empty() const
    {
        return *this == crypto_signature_t();
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
     * Use this method instead of sizeof(crypto_signature_t) to get the resulting size of the value in bytes
     * @return
     */
    [[nodiscard]] size_t size() const
    {
        return sizeof(bytes);
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
     * Encodes a signature as a hexadecimal string
     * @return
     */
    [[nodiscard]] std::string to_string() const
    {
        return Crypto::StringTools::to_hex(bytes, sizeof(bytes));
    }

  private:
    /**
     * Loads a signature from a hexademical string
     * @param s
     */
    void from_string(const std::string &s)
    {
        const auto input = Crypto::StringTools::from_hex(s);

        if (input.size() < size())
        {
            throw std::runtime_error("Could not load signature");
        }

        std::copy(input.begin(), input.end(), std::begin(bytes));
    }

    /**
     * A signature is composes of two scalars concatenated together such that S = (L || R)
     */
    struct signature_scalars
    {
        crypto_scalar_t L;
        crypto_scalar_t R;
    };

  public:
    /**
     * Provides an easy to reference structure for the signature of either the concatenated
     * L and R values together as a single 64 bytes or via the individual L & R scalars
     */
    union
    {
        signature_scalars LR;
        uint8_t bytes[64] = {0};
    };
};

/**
 * Providing overloads into the std namespace such that we can easily included
 * points, scalars, and signatures in output streams
 */
namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_point_t &value)
    {
        os << value.to_string();

        return os;
    }

    inline ostream &operator<<(ostream &os, const crypto_scalar_t &value)
    {
        os << value.to_string();

        return os;
    }

    inline ostream &operator<<(ostream &os, const crypto_signature_t &value)
    {
        os << value.to_string();

        return os;
    }
} // namespace std

#endif // CRYPTO_TYPES_H
