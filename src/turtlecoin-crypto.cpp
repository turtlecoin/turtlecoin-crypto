// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <turtlecoin-crypto.h>

#include <StringTools.h>

#include <string.h>

#ifndef NO_CRYPTO_EXPORTS
# ifdef _WIN32
#   include <windows.h>
#   ifdef _MANAGED
#     pragma managed(push, off)
#   endif

EXPORTDLL bool DllMain(
    HMODULE		/*hModule*/,
    DWORD		ul_reason_for_call,
    LPVOID		/*lpReserved*/
)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return true;
}

#   ifdef _MANAGED
#     pragma managed(pop)
#   endif
# endif
#endif

namespace Core
{
    inline Crypto::BinaryArray toBinaryArray(const std::string input)
    {
        return Common::fromHex(input);
    }

    /* Hashing Methods */
    std::string Cryptography::cn_fast_hash(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_fast_hash(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_lite_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_lite_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_lite_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_lite_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_lite_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_lite_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_dark_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_dark_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_dark_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_dark_lite_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_lite_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_dark_lite_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_lite_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_dark_lite_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_lite_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_turtle_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_turtle_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_turtle_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_turtle_lite_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_lite_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_turtle_lite_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_lite_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_turtle_lite_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_lite_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_soft_shell_slow_hash_v0(const std::string input, const uint64_t height)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_soft_shell_slow_hash_v0(data.data(), data.size(), hash, height);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_soft_shell_slow_hash_v1(const std::string input, const uint64_t height)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_soft_shell_slow_hash_v1(data.data(), data.size(), hash, height);

        return Common::podToHex(hash);
    }

    std::string Cryptography::cn_soft_shell_slow_hash_v2(const std::string input, const uint64_t height)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_soft_shell_slow_hash_v2(data.data(), data.size(), hash, height);

        return Common::podToHex(hash);
    }

    std::string Cryptography::chukwa_slow_hash(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::chukwa_slow_hash(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string Cryptography::tree_hash(const std::vector<std::string> hashes)
    {
        std::vector<Crypto::Hash> treeHashes;

        for (const auto hash : hashes)
        {
            Crypto::Hash tempHash = Crypto::Hash();

            Common::podFromHex(hash, tempHash);

            treeHashes.push_back(tempHash);
        }

        Crypto::Hash treeHash = Crypto::Hash();

        Crypto::tree_hash(treeHashes.data(), treeHashes.size(), treeHash);

        return Common::podToHex(treeHash);
    }

    std::string Cryptography::tree_branch(const std::vector<std::string> hashes)
    {
        std::vector<Crypto::Hash> _hashes;

        for (const auto hash : hashes)
        {
            Crypto::Hash tempHash = Crypto::Hash();

            Common::podFromHex(hash, tempHash);

            _hashes.push_back(tempHash);
        }

        std::vector<Crypto::Hash> _branches(1);

        Crypto::tree_branch(_hashes.data(), _hashes.size(), _branches.data());

        return Common::podToHex(_branches[0]);
    }

    std::string Cryptography::tree_hash_from_branch(const std::vector<std::string> branches, const std::string leaf, const std::string path)
    {
        std::vector<Crypto::Hash> _branches;

        for (const auto branch : branches)
        {
            Crypto::Hash _branch = Crypto::Hash();

            Common::podFromHex(branch, _branch);

            _branches.push_back(_branch);
        }

        Crypto::Hash _leaf = Crypto::Hash();

        Common::podFromHex(leaf, _leaf);

        Crypto::Hash _path = Crypto::Hash();

        Common::podFromHex(path, _path);

        Crypto::Hash _hash = Crypto::Hash();

        Crypto::tree_hash_from_branch(_branches.data(), branches.size(), _leaf, _path.data, _hash);

        return Common::podToHex(_hash);
    }

    /* Crypto Methods */
    bool Cryptography::generateRingSignatures(
        const std::string prefixHash,
        const std::string keyImage,
        const std::vector<std::string> publicKeys,
        const std::string transactionSecretKey,
        const uint64_t realOutputIndex,
        std::vector<std::string>& signatures
    )
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::KeyImage _keyImage = Crypto::KeyImage();

        Common::podFromHex(keyImage, _keyImage);

        std::vector<Crypto::PublicKey> _publicKeys;

        for (const auto publicKey : publicKeys)
        {
            Crypto::PublicKey _publicKey = Crypto::PublicKey();

            Common::podFromHex(publicKey, _publicKey);

            _publicKeys.push_back(_publicKey);
        }

        Crypto::SecretKey _transactionSecretKey;

        Common::podFromHex(transactionSecretKey, _transactionSecretKey);

        std::vector<Crypto::Signature> _signatures;

        bool success = Crypto::crypto_ops::generateRingSignatures(
            _prefixHash,
            _keyImage,
            _publicKeys,
            _transactionSecretKey,
            realOutputIndex,
            _signatures
        );

        signatures.clear();

        if (success)
        {
            for (const auto signature : _signatures)
            {
                signatures.push_back(Common::toHex(&signature, sizeof(signature)));
            }
        }

        return success;
    }

    bool Cryptography::checkRingSignature(
        const std::string prefixHash,
        const std::string keyImage,
        const std::vector<std::string> publicKeys,
        const std::vector<std::string> signatures
    )
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::KeyImage _keyImage = Crypto::KeyImage();

        Common::podFromHex(keyImage, _keyImage);

        std::vector<Crypto::PublicKey> _publicKeys;

        for (const auto publicKey : publicKeys)
        {
            Crypto::PublicKey _publicKey = Crypto::PublicKey();

            Common::podFromHex(publicKey, _publicKey);

            _publicKeys.push_back(_publicKey);
        }

        std::vector<Crypto::Signature> _signatures;

        for (const auto signature : signatures)
        {
            Crypto::Signature _signature = Crypto::Signature();

            Common::podFromHex(signature, _signature);

            _signatures.push_back(_signature);
        }

        return Crypto::crypto_ops::checkRingSignature(
            _prefixHash,
            _keyImage,
            _publicKeys,
            _signatures
        );
    }

    std::string Cryptography::generatePrivateViewKeyFromPrivateSpendKey(const std::string privateSpendKey)
    {
        Crypto::SecretKey _privateSpendKey = Crypto::SecretKey();

        Common::podFromHex(privateSpendKey, _privateSpendKey);

        Crypto::SecretKey privateViewKey = Crypto::SecretKey();

        Crypto::crypto_ops::generateViewFromSpend(_privateSpendKey, privateViewKey);

        return Common::podToHex(privateViewKey);
    }

    void Cryptography::generateViewKeysFromPrivateSpendKey(const std::string privateSpendKey, std::string& privateViewKey, std::string& publicViewKey)
    {
        Crypto::SecretKey _privateSpendKey = Crypto::SecretKey();

        Common::podFromHex(privateSpendKey, _privateSpendKey);

        Crypto::SecretKey _privateViewKey = Crypto::SecretKey();

        Crypto::PublicKey _publicViewKey = Crypto::PublicKey();

        Crypto::crypto_ops::generateViewFromSpend(_privateSpendKey, _privateViewKey, _publicViewKey);

        privateViewKey = Common::podToHex(_privateViewKey);

        publicViewKey = Common::podToHex(_publicViewKey);
    }

    void Cryptography::generateKeys(std::string& privateKey, std::string& publicKey)
    {
        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Crypto::generate_keys(_publicKey, _privateKey);

        privateKey = Common::podToHex(_privateKey);

        publicKey = Common::podToHex(_publicKey);
    }

    bool Cryptography::checkKey(const std::string publicKey)
    {
        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        return Crypto::check_key(_publicKey);
    }

    bool Cryptography::secretKeyToPublicKey(const std::string privateKey, std::string& publicKey)
    {
        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        bool success = Crypto::secret_key_to_public_key(_privateKey, _publicKey);

        if (success)
        {
            publicKey = Common::podToHex(_publicKey);
        }

        return success;
    }

    bool Cryptography::generateKeyDerivation(const std::string publicKey, const std::string privateKey, std::string& derivation)
    {
        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        bool success = Crypto::generate_key_derivation(_publicKey, _privateKey, _derivation);

        if (success)
        {
            derivation = Common::podToHex(_derivation);
        }

        return success;
    }

    bool Cryptography::derivePublicKey(const std::string derivation, const uint64_t outputIndex, const std::string publicKey, std::string& derivedKey)
    {
        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        Common::podFromHex(derivation, _derivation);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::PublicKey _derivedKey = Crypto::PublicKey();

        bool success = Crypto::derive_public_key(_derivation, outputIndex, _publicKey, _derivedKey);

        if (success)
        {
            derivedKey = Common::podToHex(_derivedKey);
        }

        return success;
    }

    std::string Cryptography::deriveSecretKey(const std::string derivation, const uint64_t outputIndex, const std::string privateKey)
    {
        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        Common::podFromHex(derivation, _derivation);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::SecretKey _derivedKey = Crypto::SecretKey();

        Crypto::derive_secret_key(_derivation, outputIndex, _privateKey, _derivedKey);

        return Common::podToHex(_derivedKey);
    }

    bool Cryptography::underivePublicKey(const std::string derivation, const uint64_t outputIndex, const std::string derivedKey, std::string& publicKey)
    {
        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        Common::podFromHex(derivation, _derivation);

        Crypto::PublicKey _derivedKey = Crypto::PublicKey();

        Common::podFromHex(derivedKey, _derivedKey);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        bool success = Crypto::underive_public_key(_derivation, outputIndex, _derivedKey, _publicKey);

        if (success)
        {
            publicKey = Common::podToHex(_publicKey);
        }

        return success;
    }

    std::string Cryptography::generateSignature(const std::string prefixHash, const std::string publicKey, const std::string privateKey)
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::Signature _signature = Crypto::Signature();

        Crypto::generate_signature(_prefixHash, _publicKey, _privateKey, _signature);

        return Common::podToHex(_signature);
    }

    bool Cryptography::checkSignature(const std::string prefixHash, const std::string publicKey, const std::string signature)
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::Signature _signature = Crypto::Signature();

        Common::podFromHex(signature, _signature);

        return Crypto::check_signature(_prefixHash, _publicKey, _signature);
    }

    std::string Cryptography::generateKeyImage(const std::string publicKey, const std::string privateKey)
    {
        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::KeyImage _keyImage = Crypto::KeyImage();

        Crypto::generate_key_image(_publicKey, _privateKey, _keyImage);

        return Common::podToHex(_keyImage);
    }

    std::string Cryptography::scalarmultKey(const std::string keyImageA, const std::string keyImageB)
    {
        Crypto::KeyImage _keyImageA = Crypto::KeyImage();

        Common::podFromHex(keyImageA, _keyImageA);

        Crypto::KeyImage _keyImageB = Crypto::KeyImage();

        Common::podFromHex(keyImageB, _keyImageB);

        Crypto::KeyImage _keyImage = Crypto::scalarmultKey(_keyImageA, _keyImageB);

        return Common::podToHex(_keyImage);
    }

    std::string Cryptography::hashToEllipticCurve(const std::string hash)
    {
        Crypto::Hash _hash = Crypto::Hash();

        Common::podFromHex(hash, _hash);

        Crypto::PublicKey _ellipticCurve = Crypto::PublicKey();

        Crypto::hash_data_to_ec(_hash.data, sizeof(_hash.data), _ellipticCurve);

        return Common::podToHex(_ellipticCurve);
    }

    std::string Cryptography::scReduce32(const std::string data)
    {
        Crypto::EllipticCurveScalar _scalar;

        Common::podFromHex(data, _scalar);

        Crypto::scReduce32(_scalar);

        return Common::podToHex(_scalar);
    }

    std::string Cryptography::hashToScalar(const std::string hash)
    {
        Crypto::BinaryArray _hash = toBinaryArray(hash);

        Crypto::EllipticCurveScalar _scalar;

        Crypto::hashToScalar(_hash.data(), _hash.size(), _scalar);

        return Common::podToHex(_scalar);
    }
}

inline void tree_hash(const char* hashes, const uint64_t hashesLength, char* &hash)
{
    const std::string* hashesBuffer = reinterpret_cast<const std::string*>(hashes);

    std::vector<std::string> _hashes(hashesBuffer, hashesBuffer + hashesLength);

    std::string result = Core::Cryptography::tree_hash(_hashes);

    hash = strdup(result.c_str());
}

inline void tree_branch(const char* hashes, const uint64_t hashesLength, char* &branch)
{
    const std::string* hashesBuffer = reinterpret_cast<const std::string*>(hashes);

    std::vector<std::string> _hashes(hashesBuffer, hashesBuffer + hashesLength);

    std::string _branch = Core::Cryptography::tree_branch(_hashes);

    branch = strdup(_branch.c_str());
}

inline void tree_hash_from_branch(const char* branches, const uint64_t branchesLength, const char* leaf, const char* path, char* &hash)
{
    const std::string* branchesBuffer = reinterpret_cast<const std::string*>(branches);

    std::vector<std::string> _branches(branchesBuffer, branchesBuffer + branchesLength);

    std::string _hash = Core::Cryptography::tree_hash_from_branch(_branches, leaf, path);

    hash = strdup(_hash.c_str());
}

inline int generateRingSignatures(
    const char* prefixHash,
    const char* keyImage,
    const char* publicKeys,
    uint64_t publicKeysLength,
    const char* transactionSecretKey,
    const uint64_t realOutputIndex,
    char* &signatures
)
{
    const std::string* publicKeysBuffer = reinterpret_cast<const std::string*>(publicKeys);

    std::vector<std::string> _publicKeys(publicKeysBuffer, publicKeysBuffer + publicKeysLength);

    std::vector<std::string> _signatures;

    bool success = Core::Cryptography::generateRingSignatures(
        prefixHash,
        keyImage,
        _publicKeys,
        transactionSecretKey,
        realOutputIndex,
        _signatures
    );

    if (success)
    {
        signatures = reinterpret_cast<char*>(_signatures.data());
    }

    return success;
}

inline bool checkRingSignature(
    const char* prefixHash,
    const char* keyImage,
    const char* publicKeys,
    const uint64_t publicKeysLength,
    const char* signatures,
    const uint64_t signaturesLength
)
{
    const std::string* publicKeysBuffer = reinterpret_cast<const std::string*>(publicKeys);

    std::vector<std::string> _publicKeys(publicKeysBuffer, publicKeysBuffer + publicKeysLength);

    const std::string* signaturesBuffer = reinterpret_cast<const std::string*>(signatures);

    std::vector<std::string> _signatures(signaturesBuffer, signaturesBuffer + signaturesLength);

    return Core::Cryptography::checkRingSignature(prefixHash, keyImage, _publicKeys, _signatures);
}

inline void generateViewKeysFromPrivateSpendKey(const char* privateSpendKey, char* &privateKey, char* &publicKey)
{
    std::string _privateKey;

    std::string _publicKey;

    Core::Cryptography::generateViewKeysFromPrivateSpendKey(privateSpendKey, _privateKey, _publicKey);

    privateKey = strdup(_privateKey.c_str());

    publicKey = strdup(_publicKey.c_str());
}

inline void generateKeys(char* &privateKey, char* &publicKey)
{
    std::string _privateKey;

    std::string _publicKey;

    Core::Cryptography::generateKeys(_privateKey, _publicKey);

    privateKey = strdup(_privateKey.c_str());

    publicKey = strdup(_publicKey.c_str());
}

inline int secretKeyToPublicKey(const char* privateKey, char* &publicKey)
{
    std::string _publicKey;

    bool success = Core::Cryptography::secretKeyToPublicKey(privateKey, _publicKey);

    publicKey = strdup(_publicKey.c_str());

    return success;
}

inline int generateKeyDerivation(const char* publicKey, const char* privateKey, char* &derivation)
{
    std::string _derivation;

    bool success = Core::Cryptography::generateKeyDerivation(publicKey, privateKey, _derivation);

    derivation = strdup(_derivation.c_str());

    return success;
}

inline int derivePublicKey(const char* derivation, const uint64_t outputIndex, const char* publicKey, char* &outPublicKey)
{
    std::string _outPublicKey;

    bool success = Core::Cryptography::derivePublicKey(derivation, outputIndex, publicKey, _outPublicKey);

    outPublicKey = strdup(_outPublicKey.c_str());

    return success;
}

inline int underivePublicKey(const char* derivation, const uint64_t outputIndex, const char* derivedKey, char* &publicKey)
{
    std::string _publicKey;

    bool success = Core::Cryptography::underivePublicKey(derivation, outputIndex, derivedKey, _publicKey);

    publicKey = strdup(_publicKey.c_str());

    return success;
}

extern "C"
{
    /* Hashing Methods */

    EXPORTDLL void _cn_fast_hash(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_fast_hash(input).c_str());
    }

    EXPORTDLL void _cn_slow_hash_v0(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_slow_hash_v0(input).c_str());
    }

    EXPORTDLL void _cn_slow_hash_v1(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_slow_hash_v1(input).c_str());
    }

    EXPORTDLL void _cn_slow_hash_v2(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_slow_hash_v2(input).c_str());
    }

    EXPORTDLL void _cn_lite_slow_hash_v0(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_lite_slow_hash_v0(input).c_str());
    }

    EXPORTDLL void _cn_lite_slow_hash_v1(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_lite_slow_hash_v1(input).c_str());
    }

    EXPORTDLL void _cn_lite_slow_hash_v2(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_lite_slow_hash_v2(input).c_str());
    }

    EXPORTDLL void _cn_dark_slow_hash_v0(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_dark_slow_hash_v0(input).c_str());
    }

    EXPORTDLL void _cn_dark_slow_hash_v1(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_dark_slow_hash_v1(input).c_str());
    }

    EXPORTDLL void _cn_dark_slow_hash_v2(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_dark_slow_hash_v2(input).c_str());
    }

    EXPORTDLL void _cn_dark_lite_slow_hash_v0(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_dark_lite_slow_hash_v0(input).c_str());
    }

    EXPORTDLL void _cn_dark_lite_slow_hash_v1(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_dark_lite_slow_hash_v1(input).c_str());
    }

    EXPORTDLL void _cn_dark_lite_slow_hash_v2(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_dark_lite_slow_hash_v2(input).c_str());
    }

    EXPORTDLL void _cn_turtle_slow_hash_v0(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_turtle_slow_hash_v0(input).c_str());
    }

    EXPORTDLL void _cn_turtle_slow_hash_v1(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_turtle_slow_hash_v1(input).c_str());
    }

    EXPORTDLL void _cn_turtle_slow_hash_v2(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_turtle_slow_hash_v2(input).c_str());
    }

    EXPORTDLL void _cn_turtle_lite_slow_hash_v0(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_turtle_lite_slow_hash_v0(input).c_str());
    }

    EXPORTDLL void _cn_turtle_lite_slow_hash_v1(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_turtle_lite_slow_hash_v1(input).c_str());
    }

    EXPORTDLL void _cn_turtle_lite_slow_hash_v2(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::cn_turtle_lite_slow_hash_v2(input).c_str());
    }

    EXPORTDLL void _cn_soft_shell_slow_hash_v0(const char* input, const uint32_t height, char* &output)
    {
        output = strdup(Core::Cryptography::cn_soft_shell_slow_hash_v0(input, height).c_str());
    }

    EXPORTDLL void _cn_soft_shell_slow_hash_v1(const char* input, const uint32_t height, char* &output)
    {
        output = strdup(Core::Cryptography::cn_soft_shell_slow_hash_v1(input, height).c_str());
    }

    EXPORTDLL void _cn_soft_shell_slow_hash_v2(const char* input, const uint32_t height, char* &output)
    {
        output = strdup(Core::Cryptography::cn_soft_shell_slow_hash_v2(input, height).c_str());
    }

    EXPORTDLL void _chukwa_slow_hash(const char* input, char* &output)
    {
        output = strdup(Core::Cryptography::chukwa_slow_hash(input).c_str());
    }

    EXPORTDLL void _tree_hash(const char* hashes, const uint64_t hashesLength, char* &hash)
    {
        tree_hash(hashes, hashesLength, hash);
    }

    EXPORTDLL void _tree_branch(const char* hashes, const uint64_t hashesLength, char* &branch)
    {
        tree_branch(hashes, hashesLength, branch);
    }

    EXPORTDLL void _tree_hash_from_branch(const char* branches, const uint64_t branchesLength, const uint64_t depth, const char* leaf, const char* path, char* &hash)
    {
        tree_hash_from_branch(branches, branchesLength, leaf, path, hash);
    }

    /* Crypto Methods */

    EXPORTDLL int _generateRingSignatures(
        const char* prefixHash,
        const char* keyImage,
        const char* publicKeys,
        const uint64_t publicKeysLength,
        const char* transactionSecretKey,
        const uint64_t realOutputIndex,
        char* &signatures
    )
    {
        return generateRingSignatures(prefixHash, keyImage, publicKeys, publicKeysLength, transactionSecretKey, realOutputIndex, signatures);
    }

    EXPORTDLL bool _checkRingSignature(
        const char* prefixHash,
        const char* keyImage,
        const char* publicKeys,
        const uint64_t publicKeysLength,
        const char* signatures,
        const uint64_t signaturesLength
    )
    {
        return checkRingSignature(prefixHash, keyImage, publicKeys, publicKeysLength, signatures, signaturesLength);
    }

    EXPORTDLL void _generatePrivateViewKeyFromPrivateSpendKey(const char* spendPrivateKey, char* &output)
    {
        output = strdup(Core::Cryptography::generatePrivateViewKeyFromPrivateSpendKey(spendPrivateKey).c_str());
    }

    EXPORTDLL void _generateViewKeysFromPrivateSpendKey(const char* spendPrivateKey, char* &privateKey, char* &publicKey)
    {
        generateViewKeysFromPrivateSpendKey(spendPrivateKey, privateKey, publicKey);
    }

    EXPORTDLL void _generateKeys(char* &privateKey, char* &publicKey)
    {
        generateKeys(privateKey, publicKey);
    }

    EXPORTDLL int _checkKey(const char* publicKey)
    {
        return Core::Cryptography::checkKey(publicKey);
    }

    EXPORTDLL int _secretKeyToPublicKey(const char* privateKey, char* &publicKey)
    {
        return secretKeyToPublicKey(privateKey, publicKey);
    }

    EXPORTDLL int _generateKeyDerivation(const char* publicKey, const char* privateKey, char* &derivation)
    {
        return generateKeyDerivation(publicKey, privateKey, derivation);
    }

    EXPORTDLL int _derivePublicKey(const char* derivation, uint32_t outputIndex, const char* publicKey, char* &outPublicKey)
    {
        return derivePublicKey(derivation, outputIndex, publicKey, outPublicKey);
    }

    EXPORTDLL void _deriveSecretKey(const char* derivation, uint32_t outputIndex, const char* privateKey, char* &outPrivateKey)
    {
        outPrivateKey = strdup(Core::Cryptography::deriveSecretKey(derivation, outputIndex, privateKey).c_str());
    }

    EXPORTDLL int _underivePublicKey(const char* derivation, const uint64_t outputIndex, const char* derivedKey, char* &publicKey)
    {
        return underivePublicKey(derivation, outputIndex, derivedKey, publicKey);
    }

    EXPORTDLL void _generateSignature(const char* prefixHash, const char* publicKey, const char* privateKey, char* &signature)
    {
        signature = strdup(Core::Cryptography::generateSignature(prefixHash, publicKey, privateKey).c_str());
    }

    EXPORTDLL int _checkSignature(const char* prefixHash, const char* publicKey, const char* signature)
    {
        return Core::Cryptography::checkSignature(prefixHash, publicKey, signature);
    }

    EXPORTDLL void _generateKeyImage(const char* publicKey, const char* privateKey, char* &keyImage)
    {
        keyImage = strdup(Core::Cryptography::generateKeyImage(publicKey, privateKey).c_str());
    }

    EXPORTDLL void _scalarmultKey(const char* keyImageA, const char* keyImageB, char* &keyImageC)
    {
        keyImageC = strdup(Core::Cryptography::scalarmultKey(keyImageA, keyImageB).c_str());
    }

    EXPORTDLL void _hashToEllipticCurve(const char* hash, char* &ec)
    {
        ec = strdup(Core::Cryptography::hashToEllipticCurve(hash).c_str());
    }

    EXPORTDLL void _scReduce32(const char* data, char* &output)
    {
        output = strdup(Core::Cryptography::scReduce32(data).c_str());
    }

    EXPORTDLL void _hashToScalar(const char* hash, char* &output)
    {
        output = strdup(Core::Cryptography::hashToScalar(hash).c_str());
    }
}
