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

#include "crypto_common.h"

#include "hashing.h"
#include "mnemonics.h"
#include "random.h"

static const crypto_scalar_t DERIVATION_DOMAIN_0 = {0x20, 0x54, 0x75, 0x72, 0x74, 0x6c, 0x65, 0x43, 0x6f, 0x69, 0x6e,
                                                    0x20, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x20, 0x62, 0x79, 0x20,
                                                    0x49, 0x42, 0x75, 0x72, 0x6e, 0x4d, 0x79, 0x43, 0x64, 0x20};

static const crypto_scalar_t SUBWALLET_DOMAIN_0 = Crypto::hash_to_scalar(DERIVATION_DOMAIN_0);

static const crypto_scalar_t VIEWKEY_DOMAIN_0 = Crypto::hash_to_scalar(SUBWALLET_DOMAIN_0);

namespace Crypto
{
    std::tuple<bool, size_t> calculate_base2_exponent(const size_t &target_value)
    {
        const auto rounded = pow2_round(target_value);

        if (rounded != target_value)
        {
            return {false, 0};
        }

        for (size_t exponent = 0; exponent < 63; ++exponent)
        {
            const auto val = 1 << exponent;

            if (val == target_value)
            {
                return {true, exponent};
            }
        }

        return {false, 0};
    }

    bool check_torsion(const crypto_point_t &value)
    {
        if (Crypto::INV_EIGHT * (Crypto::EIGHT * value) != value || value.empty())
        {
            return false;
        }

        return true;
    }

    crypto_point_t commitment_tensor_point(const crypto_point_t &point, size_t i, size_t j, size_t k)
    {
        struct
        {
            crypto_point_t Gi;
            uint64_t i = 0, j = 0, k = 0;
        } buffer;

        buffer.Gi = point;

        buffer.i = i;

        buffer.j = j;

        buffer.k = k;

        return hash_to_point(&buffer, sizeof(buffer));
    }

    std::vector<crypto_scalar_t> convolve(const crypto_scalar_vector_t &x, const std::vector<crypto_scalar_t> &y)
    {
        if (y.size() != 2)
        {
            throw std::runtime_error("requires a degree-one polynomial");
        }

        std::vector<crypto_scalar_t> result(x.size() + 1, Crypto::ZERO);

        for (size_t i = 0; i < x.size(); ++i)
        {
            for (size_t j = 0; j < y.size(); ++j)
            {
                result[i + j] += x[i] * y[j];
            }
        }

        return result;
    }

    crypto_scalar_t derivation_to_scalar(const crypto_derivation_t &derivation, uint64_t output_index)
    {
        struct
        {
            crypto_scalar_t domain;
            uint8_t derivation[32] = {0};
            uint64_t output_index = 0;
        } buffer;

        buffer.domain = DERIVATION_DOMAIN_0;

        std::memcpy(buffer.derivation, derivation.data(), derivation.size());

        buffer.output_index = output_index;

        // Ds = [H(D || n)] mod l
        return hash_to_scalar(&buffer, sizeof(buffer));
    }

    crypto_public_key_t
        derive_public_key(const crypto_scalar_t &derivation_scalar, const crypto_public_key_t &public_key)
    {
        SCALAR_OR_THROW(derivation_scalar);

        // P = [A + (Ds * G)] mod l
        return (derivation_scalar * Crypto::G) + public_key;
    }

    crypto_secret_key_t
        derive_secret_key(const crypto_scalar_t &derivation_scalar, const crypto_secret_key_t &secret_key)
    {
        SCALAR_OR_THROW(derivation_scalar);

        // p = (Ds + a) mod l
        return derivation_scalar + secret_key;
    }

    crypto_derivation_t
        generate_key_derivation(const crypto_public_key_t &public_key, const crypto_secret_key_t &secret_key)
    {
        SCALAR_OR_THROW(secret_key);

        // D = (a * B) mod l
        return (secret_key * public_key).mul8();
    }

    crypto_key_image_t
        generate_key_image(const crypto_public_key_t &public_ephemeral, const crypto_secret_key_t &secret_ephemeral)
    {
        SCALAR_OR_THROW(secret_ephemeral);

        // I = [Hp(P) * x] mod l
        return secret_ephemeral * hash_to_point(public_ephemeral);
    }

    crypto_key_image_t generate_key_image(
        const crypto_public_key_t &public_ephemeral,
        const crypto_scalar_t &derivation_scalar,
        const std::vector<crypto_key_image_t> &partial_key_images)
    {
        SCALAR_OR_THROW(derivation_scalar);

        crypto_point_vector_t key_images(partial_key_images);

        // I_d = (Ds * P) mod l
        const auto base_key_image = generate_key_image(public_ephemeral, derivation_scalar);

        key_images.append(base_key_image);

        // I = [I_d + (pk1 + pk2 + pk3 ...)] mod l
        return key_images.dedupe_sort().sum();
    }

    crypto_key_image_t generate_key_image_v2(const crypto_scalar_t &secret_ephemeral)
    {
        // I = x * U
        return secret_ephemeral.invert() * Crypto::U;
    }

    std::tuple<crypto_public_key_t, crypto_secret_key_t> generate_keys()
    {
        crypto_secret_key_t secret_key = random_scalar();

        // A = (a * G) mod l
        return {secret_key * Crypto::G, secret_key};
    }

    std::tuple<crypto_seed_t, std::vector<std::string>, uint64_t>
        generate_wallet_seed(const std::vector<uint8_t> &extra_entropy)
    {
        const auto rnd_hash = random_hash();

        serializer_t writer;

        writer.key(rnd_hash);

        if (!extra_entropy.empty())
        {
            writer.bytes(extra_entropy);
        }

        const crypto_seed_t seed =
            Crypto::Hashing::sha3_slow_hash(writer.data(), writer.size(), SEED_GENERATION_ITERATIONS);

        const auto words = Crypto::Mnemonics::encode(seed);

        const auto [success, decoded, timestamp] = Crypto::Mnemonics::decode(words);

        if (!success)
        {
            throw std::runtime_error("Could not decode generated mnemonic phrase");
        }

        return {seed, words, timestamp};
    }

    std::tuple<crypto_public_key_t, crypto_secret_key_t>
        generate_wallet_spend_keys(const crypto_seed_t &wallet_seed, uint64_t subwallet_index)
    {
        struct
        {
            crypto_scalar_t domain;
            crypto_seed_t base;
            uint64_t idx = 0;
        } buffer;

        buffer.domain = SUBWALLET_DOMAIN_0;

        buffer.base = wallet_seed;

        buffer.idx = subwallet_index;

        const auto secret_key = hash_to_scalar(&buffer, sizeof(buffer));

        // A = (a * G) mod l
        return {secret_key * Crypto::G, secret_key};
    }

    std::tuple<crypto_public_key_t, crypto_secret_key_t> generate_wallet_view_keys(const crypto_seed_t &wallet_seed)
    {
        struct
        {
            crypto_scalar_t domain;
            crypto_seed_t base;
        } buffer;

        buffer.domain = VIEWKEY_DOMAIN_0;

        buffer.base = wallet_seed;

        const auto secret_key = hash_to_scalar(&buffer, sizeof(buffer));

        // A = (a * G) mod l
        return {secret_key * Crypto::G, secret_key};
    }

    crypto_point_t hash_to_point(const void *data, size_t length)
    {
        // hash the data
        const auto hash = Crypto::Hashing::sha3(data, length);

        // reduce the hash to a point
        return crypto_point_t::reduce(hash.bytes);
    }

    crypto_scalar_t hash_to_scalar(const void *data, size_t length)
    {
        return crypto_scalar_t(Crypto::Hashing::sha3(data, length).bytes, true);
    }

    crypto_scalar_t kronecker_delta(const crypto_scalar_t &a, const crypto_scalar_t &b)
    {
        if (a == b)
        {
            return Crypto::ONE;
        }

        return Crypto::ZERO;
    }

    size_t pow2_round(size_t value)
    {
        size_t count = 0;

        if (value && !(value & (value - 1)))
        {
            return value;
        }

        while (value != 0)
        {
            value >>= uint64_t(1);

            count++;
        }

        return uint64_t(1) << count;
    }

    crypto_hash_t random_hash()
    {
        uint8_t bytes[CRYPTO_ENTROPY_BYTES];

        Random::random_bytes(sizeof(bytes), bytes);

        return Crypto::Hashing::sha3(bytes, sizeof(bytes));
    }

    std::vector<crypto_hash_t> random_hashes(size_t count)
    {
        std::vector<crypto_hash_t> result(count);

        for (size_t i = 0; i < count; ++i)
        {
            result[i] = random_hash();
        }

        return result;
    }

    crypto_point_t random_point()
    {
        uint8_t bytes[CRYPTO_ENTROPY_BYTES];

        // Retreive some random bytes
        Random::random_bytes(sizeof(bytes), bytes);

        return hash_to_point(bytes, sizeof(bytes));
    }

    std::vector<crypto_point_t> random_points(size_t count)
    {
        std::vector<crypto_point_t> result(count);

        for (size_t i = 0; i < count; ++i)
        {
            result[i] = random_point();
        }

        return result;
    }

    crypto_scalar_t random_scalar()
    {
        uint8_t bytes[CRYPTO_ENTROPY_BYTES];

        // Retrieve some random bytes
        Random::random_bytes(sizeof(bytes), bytes);

        // hash it and return it as a scalar
        return hash_to_scalar(bytes, sizeof(bytes));
    }

    std::vector<crypto_scalar_t> random_scalars(size_t count)
    {
        std::vector<crypto_scalar_t> result(count);

        for (size_t i = 0; i < count; ++i)
        {
            result[i] = random_scalar();
        }

        return result;
    }

    std::tuple<bool, crypto_seed_t, uint64_t> restore_wallet_seed(const std::vector<std::string> &words)
    {
        return Crypto::Mnemonics::decode(words);
    }

    crypto_public_key_t secret_key_to_public_key(const crypto_secret_key_t &secret_key)
    {
        SCALAR_OR_THROW(secret_key);

        // A = (a * G) mod l
        return secret_key * Crypto::G;
    }

    crypto_public_key_t underive_public_key(
        const crypto_derivation_t &derivation,
        uint8_t output_index,
        const crypto_public_key_t &public_ephemeral)
    {
        const auto scalar = derivation_to_scalar(derivation, output_index);

        // A = [P - (Ds * G)] mod l
        return public_ephemeral - (scalar * Crypto::G);
    }
} // namespace Crypto
