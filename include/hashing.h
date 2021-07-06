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

#include "crypto_types.h"

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
