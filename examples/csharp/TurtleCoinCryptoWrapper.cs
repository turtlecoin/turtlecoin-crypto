// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

using System;
using System.Runtime.InteropServices;

namespace Core
{
    public class Cryptography
    {
        public struct Keys
        {
            public string privateKey;
            public string publicKey;
        }

        private const int MinimumVariationBytes = 43 * 2;

        private static bool IsKey(string key)
        {
            if (key.Length % 2 == 0 && key.Length == 64) return true;

            return false;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_fast_hash([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_fast_hash(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_fast_hash(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_slow_hash_v0(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_slow_hash_v0(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_slow_hash_v1(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_slow_hash_v1(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_slow_hash_v2(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_slow_hash_v2(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_lite_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_lite_slow_hash_v0(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_lite_slow_hash_v0(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_lite_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_lite_slow_hash_v1(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_lite_slow_hash_v1(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_lite_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_lite_slow_hash_v2(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_lite_slow_hash_v2(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_dark_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_dark_slow_hash_v0(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_dark_slow_hash_v0(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_dark_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_dark_slow_hash_v1(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_dark_slow_hash_v1(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_dark_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_dark_slow_hash_v2(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_dark_slow_hash_v2(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_dark_lite_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_dark_lite_slow_hash_v0(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_dark_lite_slow_hash_v0(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_dark_lite_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_dark_lite_slow_hash_v1(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_dark_lite_slow_hash_v1(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_dark_lite_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_dark_lite_slow_hash_v2(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_dark_lite_slow_hash_v2(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_turtle_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_turtle_slow_hash_v0(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_turtle_slow_hash_v0(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_turtle_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_turtle_slow_hash_v1(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_turtle_slow_hash_v1(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_turtle_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_turtle_slow_hash_v2(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_turtle_slow_hash_v2(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtle-crypto-shared")]
        private static extern void _cn_turtle_lite_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_turtle_lite_slow_hash_v0(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_turtle_lite_slow_hash_v0(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtle-crypto-shared")]
        private static extern void _cn_turtle_lite_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_turtle_lite_slow_hash_v1(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_turtle_lite_slow_hash_v1(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtle-crypto-shared")]
        private static extern void _cn_turtle_lite_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string cn_turtle_lite_slow_hash_v2(string data)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_turtle_lite_slow_hash_v2(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_soft_shell_slow_hash_v0([MarshalAs(UnmanagedType.LPStr)]string input, UInt32 height, ref IntPtr output);

        static public string cn_soft_shell_slow_hash_v0(string data, UInt32 height)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _cn_soft_shell_slow_hash_v0(data, height, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_soft_shell_slow_hash_v1([MarshalAs(UnmanagedType.LPStr)]string input, UInt32 height, ref IntPtr output);

        static public string cn_soft_shell_slow_hash_v1(string data, UInt32 height)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_soft_shell_slow_hash_v1(data, height, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _cn_soft_shell_slow_hash_v2([MarshalAs(UnmanagedType.LPStr)]string input, UInt32 height, ref IntPtr output);

        static public string cn_soft_shell_slow_hash_v2(string data, UInt32 height)
        {
            if (data.Length % 2 != 0 || data.Length < MinimumVariationBytes) return null;

            IntPtr output = new IntPtr();

            _cn_soft_shell_slow_hash_v2(data, height, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _chukwa_slow_hash([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string chukwa_slow_hash(string data)
        {
            if (data.Length % 2 != 0) return null;

            IntPtr output = new IntPtr();

            _chukwa_slow_hash(data, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        /* tree_hash */

        /* tree_branch */

        /* tree_hash_from_branch */

        /* generateRingSignatures */

        /* checkRingSignature */

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _generatePrivateViewKeyFromPrivateSpendKey([MarshalAs(UnmanagedType.LPStr)]string spendPrivateKey, ref IntPtr viewPrivateKey);

        static public string generatePrivateViewKeyFromPrivateSpendKey(string spendPrivateKey)
        {
            if (!IsKey(spendPrivateKey)) return null;

            IntPtr viewPrivateKey = new IntPtr();

            _generatePrivateViewKeyFromPrivateSpendKey(spendPrivateKey, ref viewPrivateKey);

            return Marshal.PtrToStringAnsi(viewPrivateKey);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _generateViewKeysFromPrivateSpendKey([MarshalAs(UnmanagedType.LPStr)]string spendPrivateKey, ref IntPtr viewPrivateKey, ref IntPtr viewPublicKey);

        static public Keys generateViewKeysFromPrivateSpendKey(string spendPrivateKey)
        {
            if (!IsKey(spendPrivateKey)) return new Keys();

            IntPtr viewPrivateKey = new IntPtr();

            IntPtr viewPublicKey = new IntPtr();

            Keys viewKeys = new Keys();

            _generateViewKeysFromPrivateSpendKey(spendPrivateKey, ref viewPrivateKey, ref viewPublicKey);

            viewKeys.privateKey = Marshal.PtrToStringAnsi(viewPrivateKey);

            viewKeys.publicKey = Marshal.PtrToStringAnsi(viewPublicKey);

            return viewKeys;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _generateKeys(ref IntPtr privateKey, ref IntPtr publicKey);

        static public Keys generateKeys()
        {
            IntPtr privateKey = new IntPtr();

            IntPtr publicKey = new IntPtr();

            _generateKeys(ref privateKey, ref publicKey);

            Keys keys = new Keys();

            keys.privateKey = Marshal.PtrToStringAnsi(privateKey);

            keys.publicKey = Marshal.PtrToStringAnsi(publicKey);

            return keys;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern int _checkKey([MarshalAs(UnmanagedType.LPStr)]string publicKey);

        static public bool checkKey(string publicKey)
        {
            if (!IsKey(publicKey)) return false;

            int success = _checkKey(publicKey);

            if (success == 1) return true;

            return false;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern int _secretKeyToPublicKey([MarshalAs(UnmanagedType.LPStr)]string privateKey, ref IntPtr publicKey);

        static public string secretKeyToPublicKey(string privateKey)
        {
            if (!IsKey(privateKey)) return null;

            IntPtr publicKey = new IntPtr();

            int success = _secretKeyToPublicKey(privateKey, ref publicKey);

            if (success == 1) return Marshal.PtrToStringAnsi(publicKey);

            return null;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern int _generateKeyDerivation([MarshalAs(UnmanagedType.LPStr)]string publicKey, [MarshalAs(UnmanagedType.LPStr)]string privateKey, ref IntPtr derivation);

        static public string generateKeyDerivation(string publicKey, string privateKey)
        {
            if (!IsKey(publicKey) || !IsKey(privateKey)) return null;

            IntPtr derivation = new IntPtr();

            int success = _generateKeyDerivation(publicKey, privateKey, ref derivation);

            if (success == 1) return Marshal.PtrToStringAnsi(derivation);

            return null;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern int _derivePublicKey([MarshalAs(UnmanagedType.LPStr)]string derivation, UInt32 outputIndex, [MarshalAs(UnmanagedType.LPStr)]string publicKey, ref IntPtr derivedKey);

        static public string derivePublicKey(string derivation, UInt32 outputIndex, string publicKey)
        {
            if (!IsKey(derivation) || !IsKey(publicKey)) return null;

            IntPtr derivedKey = new IntPtr();

            int success = _derivePublicKey(derivation, outputIndex, publicKey, ref derivedKey);

            if (success == 1) return Marshal.PtrToStringAnsi(derivedKey);

            return null;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _deriveSecretKey([MarshalAs(UnmanagedType.LPStr)]string derivation, UInt32 outputIndex, [MarshalAs(UnmanagedType.LPStr)]string privateKey, ref IntPtr derivedKey);

        static public string deriveSecretKey(string derivation, UInt32 outputIndex, string privateKey)
        {
            if (!IsKey(derivation) || !IsKey(privateKey)) return null;

            IntPtr derivedKey = new IntPtr();

            _deriveSecretKey(derivation, outputIndex, privateKey, ref derivedKey);

            return Marshal.PtrToStringAnsi(derivedKey);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern int _underivePublicKey([MarshalAs(UnmanagedType.LPStr)]string derivation, UInt32 outputIndex, [MarshalAs(UnmanagedType.LPStr)]string derivedKey, ref IntPtr publicKey);

        static public string underivePublicKey(string derivation, UInt32 outputIndex, string derivedKey)
        {
            if (!IsKey(derivation) || !IsKey(derivedKey)) return null;

            IntPtr publicKey = new IntPtr();

            int success = _underivePublicKey(derivation, outputIndex, derivedKey, ref publicKey);

            if (success == 1) return Marshal.PtrToStringAnsi(publicKey);

            return null;
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _generateSignature([MarshalAs(UnmanagedType.LPStr)]string prefixHash, [MarshalAs(UnmanagedType.LPStr)]string publicKey, [MarshalAs(UnmanagedType.LPStr)]string privateKey, ref IntPtr signature);

        static public string generateSignature(string prefixHash, string publicKey, string privateKey)
        {
            if (!IsKey(prefixHash) || !IsKey(publicKey) || !IsKey(privateKey)) return null;

            IntPtr signature = new IntPtr();

            _generateSignature(prefixHash, publicKey, privateKey, ref signature);

            return Marshal.PtrToStringAnsi(signature);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern bool _checkSignature([MarshalAs(UnmanagedType.LPStr)]string prefixHash, [MarshalAs(UnmanagedType.LPStr)]string publicKey, [MarshalAs(UnmanagedType.LPStr)]string signature);

        public static bool CheckSignature(string prefixHash, string publicKey, string signature)
        {
            if (!IsKey(prefixHash) || !IsKey(publicKey)) return false;

            if (!checkKey(publicKey)) return false;

            return _checkSignature(prefixHash, publicKey, signature);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _generateKeyImage([MarshalAs(UnmanagedType.LPStr)]string publicKey, [MarshalAs(UnmanagedType.LPStr)]string privateKey, ref IntPtr keyImage);

        static public string generateKeyImage(string publicKey, string privateKey)
        {
            if (!IsKey(publicKey) || !IsKey(privateKey)) return null;

            IntPtr keyImage = new IntPtr();

            _generateKeyImage(publicKey, privateKey, ref keyImage);

            return Marshal.PtrToStringAnsi(keyImage);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _scalarmultKey([MarshalAs(UnmanagedType.LPStr)]string keyImageA, [MarshalAs(UnmanagedType.LPStr)]string keyImageB, ref IntPtr keyImageC);

        static public string scalarmultKey(string keyImageA, string keyImageB)
        {
            if (!IsKey(keyImageA) || !IsKey(keyImageB)) return null;

            IntPtr keyImageC = new IntPtr();

            _scalarmultKey(keyImageA, keyImageB, ref keyImageC);

            return Marshal.PtrToStringAnsi(keyImageC);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _hashToEllipticCurve([MarshalAs(UnmanagedType.LPStr)]string hash, ref IntPtr ec);

        static public string hashToEllipticCurve(string hash)
        {
            if (!IsKey(hash)) return null;

            IntPtr ec = new IntPtr();

            _hashToEllipticCurve(hash, ref ec);

            return Marshal.PtrToStringAnsi(ec);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _scReduce32([MarshalAs(UnmanagedType.LPStr)]string input, ref IntPtr output);

        static public string scReduce32(string input)
        {
            if (!IsKey(input)) return null;

            IntPtr output = new IntPtr();

            _scReduce32(input, ref output);

            return Marshal.PtrToStringAnsi(output);
        }

        [DllImport("turtlecoin-crypto-shared")]
        private static extern void _hashToScalar([MarshalAs(UnmanagedType.LPStr)]string hash, ref IntPtr scalar);

        static public string hashToScalar(string hash)
        {
            if (!IsKey(hash)) return null;

            IntPtr scalar = new IntPtr();

            _hashToScalar(hash, ref scalar);

            return Marshal.PtrToStringAnsi(scalar);
        }
    }
}
