// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#ifndef NO_CRYPTO_EXPORTS
# ifdef _WIN32
#      ifdef CRYPTO_EXPORTS
#         define EXPORTDLL __declspec(dllexport)
#      else
#         define EXPORTDLL __declspec(dllimport)
#      endif
# else
#   define EXPORTDLL
# endif
#else
# define EXPORTDLL
#endif

#include <crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

namespace Core
{
    class Cryptography
    {
        public:
            /* Hashing Methods */
            static std::string cn_fast_hash(const std::string data);

            static std::string cn_slow_hash_v0(const std::string data);
            static std::string cn_slow_hash_v1(const std::string data);
            static std::string cn_slow_hash_v2(const std::string data);

            static std::string cn_lite_slow_hash_v0(const std::string data);
            static std::string cn_lite_slow_hash_v1(const std::string data);
            static std::string cn_lite_slow_hash_v2(const std::string data);

            static std::string cn_dark_slow_hash_v0(const std::string data);
            static std::string cn_dark_slow_hash_v1(const std::string data);
            static std::string cn_dark_slow_hash_v2(const std::string data);

            static std::string cn_dark_lite_slow_hash_v0(const std::string data);
            static std::string cn_dark_lite_slow_hash_v1(const std::string data);
            static std::string cn_dark_lite_slow_hash_v2(const std::string data);

            static std::string cn_turtle_slow_hash_v0(const std::string data);
            static std::string cn_turtle_slow_hash_v1(const std::string data);
            static std::string cn_turtle_slow_hash_v2(const std::string data);

            static std::string cn_turtle_lite_slow_hash_v0(const std::string data);
            static std::string cn_turtle_lite_slow_hash_v1(const std::string data);
            static std::string cn_turtle_lite_slow_hash_v2(const std::string data);

            static std::string cn_soft_shell_slow_hash_v0(const std::string data, const uint64_t height);
            static std::string cn_soft_shell_slow_hash_v1(const std::string data, const uint64_t height);
            static std::string cn_soft_shell_slow_hash_v2(const std::string data, const uint64_t height);

            static std::string chukwa_slow_hash(const std::string data);

            static std::string tree_hash(const std::vector<std::string> hashes);
            static std::string tree_branch(const std::vector<std::string> hashes);
            static std::string tree_hash_from_branch(const std::vector<std::string> branches, const std::string leaf, const std::string path);

            /* Crypto Methods */
            static bool generateRingSignatures(
                const std::string prefixHash,
                const std::string keyImage,
                const std::vector<std::string> publicKeys,
                const std::string transactionSecretKey,
                const uint64_t realOutputIndex,
                std::vector<std::string>& signatures
            );
            static bool checkRingSignature(
                const std::string prefixHash,
                const std::string keyImage,
                const std::vector<std::string> publicKeys,
                const std::vector<std::string> signatures
            );
            static std::string generatePrivateViewKeyFromPrivateSpendKey(const std::string secretKey);
            static void generateViewKeysFromPrivateSpendKey(const std::string secretKey, std::string& privateViewKey, std::string& publicViewKey);
            static void generateKeys(std::string& privateKey, std::string& publicKey);
            static bool checkKey(const std::string publicKey);
            static bool secretKeyToPublicKey(const std::string secretKey, std::string& publicKey);
            static bool generateKeyDerivation(const std::string publicKey, const std::string secretKey, std::string& derivation);
            static bool derivePublicKey(const std::string derivation, const uint64_t outputIndex, const std::string publicKey, std::string& derivedPublicKey);
            static std::string deriveSecretKey(const std::string derivation, const uint64_t outputIndex, const std::string secretKey);
            static bool underivePublicKey(const std::string derivation, const uint64_t outputIndex, const std::string derivedKey, std::string& publicKey);
            static std::string generateSignature(const std::string prefixHash, const std::string publicKey, const std::string secretKey);
            static bool checkSignature(const std::string prefixHash, const std::string publicKey, const std::string signature);
            static std::string generateKeyImage(const std::string publicKey, const std::string secretKey);
            static std::string scalarmultKey(const std::string keyImageA, const std::string keyImageB);
            static std::string hashToEllipticCurve(const std::string hash);
            static std::string scReduce32(const std::string data);
            static std::string hashToScalar(const std::string hash);
    };
}

#ifdef __cplusplus
}
#endif