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

#ifndef CRYPTO_SCALAR_TRANSCRIPT_H
#define CRYPTO_SCALAR_TRANSCRIPT_H

#include "crypto_common.h"
#include "hashing.h"
#include "serializer.h"

static const crypto_scalar_t TRANSCRIPT_BASE = {0x53, 0x63, 0x61, 0x6c, 0x61, 0x72, 0x20, 0x54, 0x72, 0x61, 0x6e,
                                                0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x73, 0x20, 0x62, 0x79, 0x20,
                                                0x49, 0x42, 0x75, 0x72, 0x6e, 0x4d, 0x79, 0x43, 0x64, 0x20};

namespace Crypto
{
    /**
     * Structure provides a transcript for hashing arbitrary values in a determinisic way
     * that can be used for constructing challenge scalars during commitments
     */
    typedef struct ScalarTranscript
    {
      public:
        ScalarTranscript() {}

        template<typename T> ScalarTranscript(const T &seed)
        {
            update(seed);
        }

        template<typename T, typename U> ScalarTranscript(const T &seed, const U &seed2)
        {
            update(seed, seed2);
        }

        template<typename T, typename U, typename V> ScalarTranscript(const T &seed, const U &seed2, const V &seed3)
        {
            update(seed, seed2, seed3);
        }

        template<typename T, typename U, typename V, typename W>
        ScalarTranscript(const T &seed, const U &seed2, const V &seed3, const W &seed4)
        {
            update(seed, seed2, seed3, seed4);
        }

        template<typename T, typename U, typename V>
        ScalarTranscript(const T &seed, const U &seed2, const std::vector<V> &seed3)
        {
            update(seed3, seed, seed2);
        }

        /**
         * Returns the challenge scalar given the current state of the transcript
         *
         * @return
         */
        crypto_scalar_t challenge()
        {
            return state;
        }

        /**
         * Resets the transcript to its base state
         */
        void reset()
        {
            state = TRANSCRIPT_BASE;
        }

        /**
         * Updates the transcript with the value provided
         *
         * @tparam T
         * @param input
         */
        template<typename T> void update(const T &input)
        {
            serializer_t writer;

            writer.key(state);

            writer.key(input);

            state = Crypto::hash_to_scalar(writer.data(), writer.size());
        }

        /**
         * Updates the transcript with the values provided
         *
         * @tparam T
         * @tparam U
         * @param input
         * @param input2
         */
        template<typename T, typename U> void update(const T &input, const U &input2)
        {
            serializer_t writer;

            writer.key(state);

            writer.key(input);

            writer.key(input2);

            state = Crypto::hash_to_scalar(writer.data(), writer.size());
        }

        /**
         * Updates the transcript with the values provided
         *
         * @tparam T
         * @tparam U
         * @tparam V
         * @param input
         * @param input2
         * @param input3
         */
        template<typename T, typename U, typename V> void update(const T &input, const U &input2, const V &input3)
        {
            serializer_t writer;

            writer.key(state);

            writer.key(input);

            writer.key(input2);

            writer.key(input3);

            state = Crypto::hash_to_scalar(writer.data(), writer.size());
        }

        /**
         * Updates the transcript with the values provided
         *
         * @tparam T
         * @tparam U
         * @tparam V
         * @tparam W
         * @param input
         * @param input2
         * @param input3
         * @param input4
         */
        template<typename T, typename U, typename V, typename W>
        void update(const T &input, const U &input2, const V &input3, const W &input4)
        {
            serializer_t writer;

            writer.key(state);

            writer.key(input);

            writer.key(input2);

            writer.key(input3);

            writer.key(input4);

            state = Crypto::hash_to_scalar(writer.data(), writer.size());
        }

        /**
         * Updates the transcript with the vector of values provided
         *
         * @tparam T
         * @param input
         */
        template<typename T> void update(const std::vector<T> &input)
        {
            serializer_t writer;

            writer.key(state);

            writer.key(input);

            state = Crypto::hash_to_scalar(writer.data(), writer.size());
        }

      private:
        // default seed state for scalar transcripts
        crypto_scalar_t state = TRANSCRIPT_BASE;
    } crypto_scalar_transcript_t;
} // namespace Crypto

#endif // CRYPTO_SCALAR_TRANSCRIPT_H
