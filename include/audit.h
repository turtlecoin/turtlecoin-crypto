// Copyright (c) 2021, The TurtleCoin Developers
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

#ifndef CRYPTO_AUDIT_H
#define CRYPTO_AUDIT_H

#include "crypto_types.h"

namespace Crypto::Audit
{
    /**
     * Verifies the proof provided using the public ephemerals by decoding the Base58 proof,
     * extracting the key images, and the signatures, and then verifying those signatures if
     * all of the proofs are valid, the key images are returned as well
     *
     * @param public_ephemerals
     * @param proof
     * @return
     */
    std::tuple<bool, std::vector<crypto_key_image_t>>
        check_outputs_proof(const std::vector<crypto_public_key_t> &public_ephemerals, const std::string &proof);

    /**
     * Generates proof of having the secret ephemerals specified by generating the relevant
     * public keys, key images, and signature for each and encoding the necessary information
     * into a Base58 string that can be given to a verifier that already has the public
     * ephemerals
     *
     * @param secret_ephemerals
     * @return
     */
    std::tuple<bool, std::string> generate_outputs_proof(const std::vector<crypto_secret_key_t> &secret_ephemerals);
} // namespace Crypto::Audit

#endif
