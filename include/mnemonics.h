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

#ifndef CRYPTO_MNEMONICS_H
#define CRYPTO_MNEMONICS_H

#include "hashing.h"

#include <string>
#include <vector>

namespace Crypto::Mnemonics
{
    /**
     * Calculates the checksum index position in the word list for the given set of words
     *
     * @param words
     * @return
     */
    size_t calculate_checksum_index(const std::vector<std::string> &words);

    /**
     * Decodes a vector of mnemonic phrase words into the seed it represents
     *
     * @param words
     * @return
     */
    std::tuple<bool, crypto_seed_t, uint64_t> decode(const std::vector<std::string> &words);

    /**
     * Encodes the given seed into a vector of mnemonic phrase words
     *
     * @param wallet_seed
     * @param timestamp
     * @param auto_timestamp
     * @return
     */
    std::vector<std::string>
        encode(const crypto_seed_t &wallet_seed, uint64_t timestamp = 0, bool auto_timestamp = true);

    /**
     * Finds the index of the given word in the word list or returns -1 if not found
     *
     * @param word
     * @return
     */
    size_t word_index(const std::string &word);

    /**
     * Returns the full word list
     *
     * @return
     */
    std::vector<std::string> word_list();

    /**
     * Returns the full word list but trimmed to the minimum number of characters per word
     *
     * @return
     */
    std::vector<std::string> word_list_trimmed();
} // namespace Crypto::Mnemonics

#endif
