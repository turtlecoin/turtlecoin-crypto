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

#ifndef CRYPTO_BASE58_H
#define CRYPTO_BASE58_H

#include "hashing.h"
#include "serializer.h"

namespace Crypto::Base58
{
    /**
     * Decodes the base58 encoded string into the raw bytes
     *
     * @param input
     * @return
     */
    [[nodiscard]] std::tuple<bool, std::vector<uint8_t>> decode(const std::string &input);

    /**
     * Decodes the Base58 encoded string into the raw bytes after confirming that
     * the checksum value is correct for the raw bytes provided
     *
     * @param input
     * @return
     */
    [[nodiscard]] std::tuple<bool, std::vector<uint8_t>> decode_check(const std::string &input);

    /**
     * Encodes the raw bytes into a Base58 encoded string
     *
     * @param input
     * @return
     */
    [[nodiscard]] std::string encode(std::vector<uint8_t> input);

    /**
     * Encodes the raw bytes into a Base58 encoded string including a checksum that
     * allows for ensuring that the raw bytes included inside were not altered
     *
     * @param input
     * @return
     */
    [[nodiscard]] std::string encode_check(const std::vector<uint8_t> &input);
} // namespace Crypto::Base58

#endif // CRYPTO_BASE58_H
