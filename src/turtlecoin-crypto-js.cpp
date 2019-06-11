// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <stdio.h>

#include <stdlib.h>

#include <turtlecoin-crypto.h>

#include <emscripten/bind.h>

using namespace emscripten;

struct Keys
{
    std::string PublicKey;
    std::string SecretKey;
};

/* Most of the redefintions below are the result of the methods returning a bool instead
   of the value we need or issues with method signatures having a uint64_t */

std::string cn_soft_shell_slow_hash_v0(const std::string data, const int height)
{
    return Core::Cryptography::cn_soft_shell_slow_hash_v0(data, height);
}

std::string cn_soft_shell_slow_hash_v1(const std::string data, const int height)
{
    return Core::Cryptography::cn_soft_shell_slow_hash_v1(data, height);
}

std::string cn_soft_shell_slow_hash_v2(const std::string data, const int height)
{
    return Core::Cryptography::cn_soft_shell_slow_hash_v2(data, height);
}

std::vector<std::string> generateRingSignatures(
    const std::string prefixHash,
    const std::string keyImage,
    const std::vector<std::string> publicKeys,
    const std::string transactionSecretKey,
    const int realOutputIndex
)
{
    std::vector<std::string> signatures;

    bool success = Core::Cryptography::generateRingSignatures(
        prefixHash,
        keyImage,
        publicKeys,
        transactionSecretKey,
        realOutputIndex,
        signatures
    );

    return signatures;
}

Keys generateViewKeysFromPrivateSpendKey(const std::string secretKey)
{
    std::string viewSecretKey;

    std::string viewPublicKey;

    Core::Cryptography::generateViewKeysFromPrivateSpendKey(secretKey, viewSecretKey, viewPublicKey);

    Keys keys;

    keys.PublicKey = viewPublicKey;

    keys.SecretKey = viewSecretKey;

    return keys;
}

Keys generateKeys()
{
    std::string secretKey;

    std::string publicKey;

    Core::Cryptography::generateKeys(secretKey, publicKey);

    Keys keys;

    keys.PublicKey = publicKey;

    keys.SecretKey = secretKey;

    return keys;
}

std::string secretKeyToPublicKey(const std::string secretKey)
{
    std::string publicKey;

    bool success = Core::Cryptography::secretKeyToPublicKey(secretKey, publicKey);

    return publicKey;
}

std::string generateKeyDerivation(const std::string publicKey, const std::string secretKey)
{
    std::string derivation;

    bool success = Core::Cryptography::generateKeyDerivation(publicKey, secretKey, derivation);

    return derivation;
}

std::string derivePublicKey(const std::string derivation, const int outputIndex, const std::string publicKey)
{
    std::string derivedKey;

    bool success = Core::Cryptography::derivePublicKey(derivation, outputIndex, publicKey, derivedKey);

    return derivedKey;
}

std::string deriveSecretKey(const std::string derivation, const int outputIndex, const std::string secretKey)
{
    return Core::Cryptography::deriveSecretKey(derivation, outputIndex, secretKey);
}

std::string underivePublicKey(const std::string derivation, const int outputIndex, const std::string derivedKey)
{
    std::string publicKey;

    bool success = Core::Cryptography::underivePublicKey(derivation, outputIndex, derivedKey, publicKey);

    return publicKey;
}

EMSCRIPTEN_BINDINGS(signatures)
{
    function("cn_fast_hash", &Core::Cryptography::cn_fast_hash);

    function("cn_slow_hash_v0", &Core::Cryptography::cn_slow_hash_v0);
    function("cn_slow_hash_v1", &Core::Cryptography::cn_slow_hash_v1);
    function("cn_slow_hash_v2", &Core::Cryptography::cn_slow_hash_v2);

    function("cn_lite_slow_hash_v0", &Core::Cryptography::cn_lite_slow_hash_v0);
    function("cn_lite_slow_hash_v1", &Core::Cryptography::cn_lite_slow_hash_v1);
    function("cn_lite_slow_hash_v2", &Core::Cryptography::cn_lite_slow_hash_v2);

    function("cn_dark_slow_hash_v0", &Core::Cryptography::cn_dark_slow_hash_v0);
    function("cn_dark_slow_hash_v1", &Core::Cryptography::cn_dark_slow_hash_v1);
    function("cn_dark_slow_hash_v2", &Core::Cryptography::cn_dark_slow_hash_v2);

    function("cn_dark_lite_slow_hash_v0", &Core::Cryptography::cn_dark_lite_slow_hash_v0);
    function("cn_dark_lite_slow_hash_v1", &Core::Cryptography::cn_dark_lite_slow_hash_v1);
    function("cn_dark_lite_slow_hash_v2", &Core::Cryptography::cn_dark_lite_slow_hash_v2);

    function("cn_turtle_slow_hash_v0", &Core::Cryptography::cn_turtle_slow_hash_v0);
    function("cn_turtle_slow_hash_v1", &Core::Cryptography::cn_turtle_slow_hash_v1);
    function("cn_turtle_slow_hash_v2", &Core::Cryptography::cn_turtle_slow_hash_v2);

    function("cn_turtle_lite_slow_hash_v0", &Core::Cryptography::cn_turtle_lite_slow_hash_v0);
    function("cn_turtle_lite_slow_hash_v1", &Core::Cryptography::cn_turtle_lite_slow_hash_v1);
    function("cn_turtle_lite_slow_hash_v2", &Core::Cryptography::cn_turtle_lite_slow_hash_v2);

    function("cn_soft_shell_slow_hash_v0", &cn_soft_shell_slow_hash_v0);
    function("cn_soft_shell_slow_hash_v1", &cn_soft_shell_slow_hash_v1);
    function("cn_soft_shell_slow_hash_v2", &cn_soft_shell_slow_hash_v2);

    function("chukwa_slow_hash", &Core::Cryptography::chukwa_slow_hash);

    function("tree_hash", &Core::Cryptography::tree_hash);
    function("tree_branch", &Core::Cryptography::tree_branch);
    function("tree_hash_from_branch", &Core::Cryptography::tree_hash_from_branch);

    function("generateRingSignatures", &generateRingSignatures);
    function("checkRingSignature", &Core::Cryptography::checkRingSignature);
    function("generatePrivateViewKeyFromPrivateSpendKey", &Core::Cryptography::generatePrivateViewKeyFromPrivateSpendKey);
    function("generateViewKeysFromPrivateSpendKey", &generateViewKeysFromPrivateSpendKey);
    function("generateKeys", &generateKeys);
    function("checkKey", &Core::Cryptography::checkKey);
    function("secretKeyToPublicKey", &secretKeyToPublicKey);
    function("generateKeyDerivation", &generateKeyDerivation);
    function("derivePublicKey", &derivePublicKey);
    function("deriveSecretKey", &deriveSecretKey);
    function("underivePublicKey", &underivePublicKey);
    function("generateSignature", &Core::Cryptography::generateSignature);
    function("checkSignature", &Core::Cryptography::checkSignature);
    function("generateKeyImage", &Core::Cryptography::generateKeyImage);
    function("scalarmultKey", &Core::Cryptography::scalarmultKey);
    function("hashToEllipticCurve", &Core::Cryptography::hashToEllipticCurve);
    function("scReduce32", &Core::Cryptography::scReduce32);
    function("hashToScalar", &Core::Cryptography::hashToScalar);

    register_vector<std::string>("VectorString");

    value_object<Keys>("Keys")
        .field("SecretKey", &Keys::SecretKey)
        .field("PublicKey", &Keys::PublicKey);
}
