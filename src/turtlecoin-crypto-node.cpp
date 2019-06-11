// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <nan.h>

#include <iostream>

#include <stdio.h>

#include <v8.h>

#include <turtlecoin-crypto.h>

using BinaryArray = std::vector<uint8_t>;

/*
*
* Helper methods
*
*/

inline v8::Local<v8::Array> prepareResult(const bool success, const v8::Local<v8::Value> val)
{
    v8::Local<v8::Array> result = Nan::New<v8::Array>(2);

    /* We do the inverse of success because we want the results in [err, value] format */
    Nan::Set(result, 0, Nan::New(!success));

    Nan::Set(result, 1, val);

    return result;
}

/*
*
* Core Cryptographic Operations
*
*/

void checkKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New(false);

    std::string publicKey = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!publicKey.empty())
        {
            bool success = Core::Cryptography::checkKey(publicKey);

            functionReturnValue = Nan::New(success);
        }
    }

    info.GetReturnValue().Set(functionReturnValue);
}

void checkRingSignature(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New(false);

    std::string prefixHash = std::string();

    std::string keyImage = std::string();

    std::vector<std::string> publicKeys;

    std::vector<std::string> signatures;

    if (info.Length() == 4)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            keyImage = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[2]);

            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string hash = std::string(*Nan::Utf8String(array->Get(i)));

                publicKeys.push_back(hash);
            }
        }

        if (info[3]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[3]);

            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string hash = std::string(*Nan::Utf8String(array->Get(i)));

                signatures.push_back(hash);
            }
        }

        if (!prefixHash.empty() && !keyImage.empty() && publicKeys.size() != 0 && signatures.size() != 0)
        {
            bool success = Core::Cryptography::checkRingSignature(prefixHash, keyImage, publicKeys, signatures);

            functionReturnValue = Nan::New(success);
        }
    }

    info.GetReturnValue().Set(functionReturnValue);
}

void checkSignature(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New(false);

    std::string prefixHash = std::string();

    std::string publicKey = std::string();

    std::string signature = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            signature = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!prefixHash.empty() && !publicKey.empty() && !signature.empty())
        {
            bool success = Core::Cryptography::checkSignature(prefixHash, publicKey, signature);

            functionReturnValue = Nan::New(success);
        }
    }

    info.GetReturnValue().Set(functionReturnValue);
}

void derivePublicKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    size_t outputIndex = 0;

    std::string derivation = std::string();

    std::string publicKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            derivation =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t) info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !publicKey.empty())
        {
            std::string outPublicKey;

            bool success = Core::Cryptography::derivePublicKey(derivation, outputIndex, publicKey, outPublicKey);

            if (success)
            {
                functionReturnValue = Nan::New(outPublicKey).ToLocalChecked();

                functionSuccess = success;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void deriveSecretKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    size_t outputIndex = 0;

    std::string derivation = std::string();

    std::string secretKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            derivation = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t) info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !secretKey.empty())
        {
            std::string _secretKey;

            try
            {
                _secretKey = Core::Cryptography::deriveSecretKey(derivation, outputIndex, secretKey);
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }

            functionReturnValue = Nan::New(_secretKey).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateKeys(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string secretKey;

    std::string publicKey;

    Core::Cryptography::generateKeys(secretKey, publicKey);

    v8::Local<v8::Object> jsonObject = Nan::New<v8::Object>();

    v8::Local<v8::String> publicKeyProp = Nan::New("publicKey").ToLocalChecked();

    v8::Local<v8::String> secretKeyProp = Nan::New("secretKey").ToLocalChecked();

    v8::Local<v8::Value> publicKeyValue = Nan::New(publicKey).ToLocalChecked();

    v8::Local<v8::Value> secretKeyValue = Nan::New(secretKey).ToLocalChecked();

    Nan::Set(jsonObject, publicKeyProp, publicKeyValue);

    Nan::Set(jsonObject, secretKeyProp, secretKeyValue);

    info.GetReturnValue().Set(prepareResult(true, jsonObject));
}

void generateKeyDerivation(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string publicKey = std::string();

    std::string secretKey = std::string();

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (!secretKey.empty() && !publicKey.empty())
        {
            std::string derivation;

            bool success = Core::Cryptography::generateKeyDerivation(publicKey, secretKey, derivation);

            if (success)
            {
                functionReturnValue = Nan::New(derivation).ToLocalChecked();

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateKeyImage(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string publicKey = std::string();

    std::string secretKey = std::string();

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (!publicKey.empty() && !secretKey.empty())
        {
            std::string keyImage;

            try
            {
                keyImage = Core::Cryptography::generateKeyImage(publicKey, secretKey);
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }

            functionReturnValue = Nan::New(keyImage).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generatePrivateViewKeyFromPrivateSpendKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string secretKey = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!secretKey.empty())
        {
            try
            {
                std::string privateViewKey = Core::Cryptography::generatePrivateViewKeyFromPrivateSpendKey(secretKey);

                functionReturnValue = Nan::New(privateViewKey).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateViewKeysFromPrivateSpendKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Object> jsonObject = Nan::New<v8::Object>();

    v8::Local<v8::String> publicKeyProp = Nan::New("publicKey").ToLocalChecked();

    v8::Local<v8::String> secretKeyProp = Nan::New("secretKey").ToLocalChecked();

    bool functionSuccess = false;

    std::string secretKey = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!secretKey.empty())
        {
            try
            {
                std::string privateViewKey;

                std::string publicViewKey;

                Core::Cryptography::generateViewKeysFromPrivateSpendKey(secretKey, privateViewKey, publicViewKey);

                v8::Local<v8::Value> publicKeyValue = Nan::New(publicViewKey).ToLocalChecked();

                v8::Local<v8::Value> secretKeyValue = Nan::New(privateViewKey).ToLocalChecked();

                Nan::Set(jsonObject, publicKeyProp, publicKeyValue);

                Nan::Set(jsonObject, secretKeyProp, secretKeyValue);

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, jsonObject));
}

void generateRingSignatures(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string prefixHash = std::string();

    std::string keyImage = std::string();

    std::string transactionSecretKey = std::string();

    std::vector<std::string> publicKeys;

    uint64_t realOutput = 0;

    if (info.Length() == 5)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            keyImage = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[2]);

            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string hash = std::string(*Nan::Utf8String(array->Get(i)));

                publicKeys.push_back(hash);
            }
        }

        if (info[3]->IsString())
        {
            transactionSecretKey = std::string(*Nan::Utf8String(info[3]->ToString()));
        }

        if (info[4]->IsNumber())
        {
            realOutput = (uint64_t) info[4]->NumberValue();
        }

        if (!prefixHash.empty() && !keyImage.empty() && !transactionSecretKey.empty() && publicKeys.size() != 0)
        {
            std::vector<std::string> signatures;

            bool success = Core::Cryptography::generateRingSignatures(
                prefixHash,
                keyImage,
                publicKeys,
                transactionSecretKey,
                realOutput,
                signatures
            );

            if (success)
            {
                v8::Local<v8::Array> sigs = Nan::New <v8::Array>(signatures.size());

                for (size_t i = 0; i < signatures.size(); i++)
                {
                    v8::Local<v8::String> result = Nan::New(signatures[i]).ToLocalChecked();

                    Nan::Set(sigs, i, result);
                }

                functionReturnValue = sigs;

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateSignature(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string prefixHash = std::string();

    std::string publicKey = std::string();

    std::string secretKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!prefixHash.empty() && !publicKey.empty() && !secretKey.empty())
        {
            std::string signature;

            try
            {
                signature = Core::Cryptography::generateSignature(prefixHash, publicKey, secretKey);
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }

            functionReturnValue = Nan::New(signature).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void hashToEllipticCurve(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string hash = std::string();

    std::string scalar = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            hash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!hash.empty())
        {
            try
            {
                std::string _ec = Core::Cryptography::hashToEllipticCurve(hash);

                functionReturnValue = Nan::New(_ec).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void hashToScalar(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    std::string scalar = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string _scalar = Core::Cryptography::hashToScalar(data);

                functionReturnValue = Nan::New(_scalar).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void scalarmultKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string keyImageA = std::string();

    std::string keyImageB = std::string();

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            keyImageA = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            keyImageB = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (!keyImageA.empty() && !keyImageB.empty())
        {
            try
            {
                std::string keyImageC = Core::Cryptography::scalarmultKey(keyImageA, keyImageB);

                functionReturnValue = Nan::New(keyImageC).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void scReduce32(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string scalar = Core::Cryptography::scReduce32(data);

                functionReturnValue = Nan::New(scalar).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void secretKeyToPublicKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string secretKey = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!secretKey.empty())
        {
            std::string publicKey;

            bool success = Core::Cryptography::secretKeyToPublicKey(secretKey, publicKey);

            if (success)
            {
                functionReturnValue = Nan::New(publicKey).ToLocalChecked();

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void tree_hash(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::vector<std::string> hashes;

    if (info.Length() == 1)
    {
        if (info[0]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[0]);

            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string hash = std::string(*Nan::Utf8String(array->Get(i)));

                hashes.push_back(hash);
            }
        }

        if (hashes.size() != 0)
        {
            try
            {
                std::string hash = Core::Cryptography::tree_hash(hashes);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void tree_branch(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::vector<std::string> hashes;

    if (info.Length() == 1)
    {
        if (info[0]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[0]);

            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string hash = std::string(*Nan::Utf8String(array->Get(i)));

                hashes.push_back(hash);
            }
        }

        if (hashes.size() != 0)
        {
            try
            {
                std::string branch = Core::Cryptography::tree_branch(hashes);

                functionReturnValue = Nan::New(branch).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void tree_hash_from_branch(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::vector<std::string> branches;

    std::string leaf = std::string();

    std::string path = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[0]);

            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string hash = std::string(*Nan::Utf8String(array->Get(i)));

                branches.push_back(hash);
            }
        }

        if (info[1]->IsString())
        {
            leaf = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (info[2]->IsString())
        {
            path = std::string(*Nan::Utf8String(info[3]->ToString()));
        }

        if (branches.size() != 0 && !leaf.empty() && !path.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::tree_hash_from_branch(branches, leaf, path);

                functionReturnValue = Nan::New(hash).ToLocalChecked();;

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void underivePublicKey(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    size_t outputIndex = 0;

    std::string derivation = std::string();

    std::string derivedKey = std::string();

    if (info.Length() == 3)
    {

        if (info[0]->IsString())
        {
            derivation = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t) info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            derivedKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !derivedKey.empty())
        {
            try
            {
                std::string publicKey;

                bool success = Core::Cryptography::underivePublicKey(derivation, outputIndex, derivedKey, publicKey);

                if (success)
                {
                    functionReturnValue = Nan::New(publicKey).ToLocalChecked();

                    functionSuccess = true;
                }
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/*
*
* Hashing Operations
*
*/

void cn_fast_hash(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_fast_hash(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Cryptonight Variants */

void cn_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_slow_hash_v0(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_slow_hash_v1(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_slow_hash_v2(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Cryptonight Lite Variants */

void cn_lite_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_lite_slow_hash_v0(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_lite_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_lite_slow_hash_v1(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_lite_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_lite_slow_hash_v2(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Cryptonight Dark Variants */

void cn_dark_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_dark_slow_hash_v0(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_dark_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_dark_slow_hash_v1(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_dark_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_dark_slow_hash_v2(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Cryptonight Dark Lite Variants */

void cn_dark_lite_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_dark_lite_slow_hash_v0(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_dark_lite_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_dark_lite_slow_hash_v1(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_dark_lite_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_dark_lite_slow_hash_v2(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Cryptonight Turtle Variants */

void cn_turtle_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_turtle_slow_hash_v0(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_turtle_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_turtle_slow_hash_v1(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_turtle_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_turtle_slow_hash_v2(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Cryptonight Turtle Lite Variants */

void cn_turtle_lite_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_turtle_lite_slow_hash_v0(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_turtle_lite_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_turtle_lite_slow_hash_v1(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void cn_turtle_lite_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::cn_turtle_lite_slow_hash_v2(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/* Chukwa */

void chukwa_slow_hash(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();

    bool functionSuccess = false;

    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            try
            {
                std::string hash = Core::Cryptography::chukwa_slow_hash(data);

                functionReturnValue = Nan::New(hash).ToLocalChecked();

                functionSuccess = true;
            }
            catch(const std::exception & e)
            {
                return Nan::ThrowError(e.what());
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void InitModule(v8::Local<v8::Object> exports)
{
    /* Core Cryptographic Operations */
    exports->Set(Nan::New("checkKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (checkKey)->GetFunction());

    exports->Set(Nan::New("checkRingSignature").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (checkRingSignature)->GetFunction());

    exports->Set(Nan::New("checkSignature").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (checkSignature)->GetFunction());

    exports->Set(Nan::New("derivePublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (derivePublicKey)->GetFunction());

    exports->Set(Nan::New("deriveSecretKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (deriveSecretKey)->GetFunction());

    exports->Set(Nan::New("generateKeys").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generateKeys)->GetFunction());

    exports->Set(Nan::New("generateKeyDerivation").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generateKeyDerivation)->GetFunction());

    exports->Set(Nan::New("generateKeyImage").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generateKeyImage)->GetFunction());

    exports->Set(Nan::New("generatePrivateViewKeyFromPrivateSpendKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generatePrivateViewKeyFromPrivateSpendKey)->GetFunction());

    exports->Set(Nan::New("generateViewKeysFromPrivateSpendKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generateViewKeysFromPrivateSpendKey)->GetFunction());

    exports->Set(Nan::New("generateRingSignatures").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generateRingSignatures)->GetFunction());

    exports->Set(Nan::New("generateSignature").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (generateSignature)->GetFunction());

    exports->Set(Nan::New("hashToEllipticCurve").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (hashToEllipticCurve)->GetFunction());

    exports->Set(Nan::New("hashToScalar").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (hashToScalar)->GetFunction());

    exports->Set(Nan::New("scalarmultKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (scalarmultKey)->GetFunction());

    exports->Set(Nan::New("scReduce32").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (scReduce32)->GetFunction());

    exports->Set(Nan::New("secretKeyToPublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (secretKeyToPublicKey)->GetFunction());

    exports->Set(Nan::New("tree_hash").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (tree_hash)->GetFunction());

    exports->Set(Nan::New("tree_branch").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (tree_branch)->GetFunction());

    exports->Set(Nan::New("tree_hash_from_branch").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (tree_hash_from_branch)->GetFunction());

    exports->Set(Nan::New("underivePublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (underivePublicKey)->GetFunction());

    /* Hashing Operations */
    exports->Set(Nan::New("cnFastHash").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_fast_hash)->GetFunction());

    exports->Set(Nan::New("cn_fast_hash").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_fast_hash)->GetFunction());

    exports->Set(Nan::New("cn_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("cn_lite_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_lite_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_lite_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_lite_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_lite_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_lite_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("cn_dark_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_dark_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_dark_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_dark_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_dark_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_dark_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("cn_dark_lite_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_dark_lite_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_dark_lite_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_dark_lite_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_dark_lite_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_dark_lite_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("cn_turtle_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_turtle_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_turtle_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_turtle_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_turtle_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_turtle_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_turtle_lite_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_turtle_lite_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (cn_turtle_lite_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("chukwa_slow_hash").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>
                 (chukwa_slow_hash)->GetFunction());
}

NODE_MODULE(turtlecoincrypto, InitModule);
