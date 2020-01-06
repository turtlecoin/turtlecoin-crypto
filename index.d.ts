// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

declare module "turtlecoin-crypto" {
    /**
     * Whether the module is using native JS or WASM methods
     */
    export function isNative(): boolean;

    /**
     * Whether the module is loaded and ready
     */
    export function isReady(): boolean;

    /**
     * Checks that the given key is a valid public key
     * 
     * @param key   the public key to check
     * 
     * @returns {boolean} whether the key is a valid public key
     */
    export function checkKey(
        key: string): boolean;

    /**
     * Validates that the ring signatures provided are valid
     * 
     * @param transactionPrefixHash the transaction prefix hash
     * @param keyImage              the key image that the signature pertains to
     * @param inputKeys             the input keys used in the ring
     * @param signatures            the signatures to verify
     * 
     * @returns {boolean} whether the signatures are valid or not
     */
    export function checkRingSignatures(
        transactionPrefixHash: string,
        keyImage: string,
        inputKeys: string[],
        signatures: string[]): boolean

    /**
     * Checks an individual signature
     * 
     * @param hash      the input hash
     * @param publicKey the public key used
     * @param signature the signature to check
     * 
     * @returns {boolean} whether the signature is valid
     */
    export function checkSignature(
        hash: string,
        publicKey: string,
        signature: string): boolean;

    /**
     * CryptoNight Fast Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    function cn_fast_hash(
        data: string): Array<boolean|string>;

    /**
     * Derives the public key from the specified parameters
     * 
     * @param derivation    the derivation
     * @param outputIndex   the output index in the transaction
     * @param publicKey     the public key
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, publicKey]
     */
    export function derivePublicKey(
        derivation: string,
        outputIndex: number,
        publicKey: string): Array<boolean|string>;

    /**
     * Derives the secret key from the specified parameters
     * 
     * @param derivation    the derivation
     * @param outputIndex   the output index in the transaction
     * @param secretKey     the secret key
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, secretKey]
     */
    export function deriveSecretKey(
        derivation: string,
        outputIndex: number,
        secretKey: string): Array<boolean|string>;

    /**
     * Generates a deterministic subwallet key pair
     * 
     * @param privateKey    the private spend key
     * @param walletIndex   the wallet index depth
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function generateDeterministicSubwalletKeys(
        privateKey: string,
        walletIndex: number): Array<boolean|{publicKey: string, secretKey: string}>;

    /**
     * Generates the key derivation of the given keys
     * 
     * @param transactionPublicKey  the transaction public key
     * @param privateViewKey        the private view key
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, derivation]
     */
    export function generateKeyDerivation(
        transactionPublicKey: string,
        privateViewKey: string): Array<boolean|string>;

    /**
     * Generates the key  image from the given public and private keys
     * 
     * @param publicKey     the public emphemeral
     * @param privateKey    the private emphemeral
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, keyImage]
     */
    export function generateKeyImage(
        publicKey: string,
        privateKey: string): Array<boolean|string>;

    /**
     * Generates a key pair
     * 
     * @returns {Array.<boolean|{publicKey: string, secretKey: string}>} array consisting of [error, keys]
     */
    export function generateKeys(): Array<boolean|{publicKey: string, secretKey: string}>;

    /**
     * Generates the deterministic private view key from the supplied private spend key
     * 
     * @param privateKey    the private spend key
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, privateViewKey]
     */
    export function generatePrivateViewKeyFromPrivateSpendKey(
        privateKey: string): Array<boolean|string>;

    /**
     * Generates the ring signatures for the supplied parameters
     * 
     * @param transactionPrefixHash the transaction prefix hash
     * @param keyImage              the key image that the signature pertains to
     * @param inputKeys             the input keys used in the ring
     * @param privateKey            the real private key used for signing
     * @param realIndex             the index of the real output in the inputKeys array
     * 
     * @returns {Array.<boolean|string[]>} array consisting of [error, signatures[]]
     */
    export function generateRingSignatures(
        transactionPrefixHash: string,
        keyImage: string,
        inputKeys: string[],
        privateKey: string,
        realIndex: number): Array<boolean|string[]>;

    /**
     * Generates a single signature
     * 
     * @param hash          the input hash
     * @param publicKey     the public key to use
     * @param privateKey    the private key to use for the signing process
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, signature]
     */
    export function generateSignature(
        hash: string,
        publicKey: string,
        privateKey: string): Array<boolean|string>;

    /**
     * Generates the deterministic view keys from the supplied private spend key
     * 
     * @param privateKey    the private spend key
     * 
     * @returns {Array.<boolean|{publicKey: string, secretKey: string}}>} array consisting of [error, keys]
     */
    export function generateViewKeysFromPrivateSpendKey(
        privateKey: string): Array<boolean|{publicKey: string, secretKey: string}>;

    /**
     * Converts a hash to an elliptic curve
     * 
     * @param hash  the hash to convert
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, ellipticCurve]
     */
    export function hashToEllipticCurve(
        hash: string): Array<boolean|string>;

    /**
     * Converts a hash to a scalar
     * 
     * @param hash  the hash to convert
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, scalar]
     */
    export function hashToScalar(
        hash: string): Array<boolean|string>;

    /**
     * Performs a scalar multkey operation
     * 
     * @param keyImageA the first key image
     * @param keyImageB the second key image
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, keyImage]
     */
    export function scalarmultKey(
        keyImageA: string,
        keyImageB: string): Array<boolean|string>;

    /**
     * scalar 32-bit reduction
     * 
     * @param data  hexadecimal data to reduce
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, result]
     */
    export function scReduce32(
        data: string): Array<boolean|string>;

    /**
     * Generates the public key from the private key
     * 
     * @param privateKey    the private key
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, publicKey]
     */
    export function secretKeyToPublicKey(
        privateKey: string): Array<boolean|string>;

    /**
     * Calculates the tree branch of the given hashes
     * 
     * @param arr   the hashes to use in the calculation
     * 
     * @returns {Array.<boolean|string[]>} array consisting of [error, treeBranches[]]
     */
    export function tree_branch(
        arr: string[]): Array<boolean|string[]>;

    /**
     * Calculates the tree depth of the given value
     * 
     * @param count the number of items
     * 
     * @returns {Array.<boolean|number>} array consisting of [error, depth]
     */
    export function tree_depth(
        count: number): Array<boolean|number>;

    /**
     * Calculates the tree hash of the given hashes
     * 
     * @param arr   the hashes to use in the calculation
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, treeHash]
     */
    export function tree_hash(
        arr: string[]): Array<boolean|string>;

    /**
     * Calculates the tree hash of the given branches
     * 
     * @param branches  the hashes of the branches to use in the calculation
     * @param leaf      the leaf to include in the calculation
     * @param path      the path to include in the calculation
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, treeHash]
     */
    export function tree_hash_from_branch(
        branches: string[],
        leaf: string,
        path: number): Array<boolean|string>;

    /**
     * Underives the public key from the given parameters
     * 
     * @param derivation    the derivation
     * @param outputIndex   the output index in the transaction
     * @param outputKey     the output key
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, publicKey]
     */
    export function underivePublicKey(
        derivation: string,
        outputIndex: number,
        outputKey: string): Array<boolean|string>;

    /**
     * CryptoNight v0 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_slow_hash_v0(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight v1 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_slow_hash_v1(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight v2 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_slow_hash_v2(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Lite v0 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_lite_slow_hash_v0(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Lite v1 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_lite_slow_hash_v1(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Lite v2 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_lite_slow_hash_v2(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Dark v0 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_dark_slow_hash_v0(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Dark v1 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_dark_slow_hash_v1(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Dark v2 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_dark_slow_hash_v2(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Dark Lite v0 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_dark_lite_slow_hash_v0(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Dark Lite v1 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_dark_lite_slow_hash_v1(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Dark Lite v2 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_dark_lite_slow_hash_v2(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Turtle v0 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_turtle_slow_hash_v0(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Turtle v1 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_turtle_slow_hash_v1(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Turtle v2 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_turtle_slow_hash_v2(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Turtle Lite v0 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_turtle_lite_slow_hash_v0(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Turtle Lite v1 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_turtle_lite_slow_hash_v1(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Turtle Lite v2 Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_turtle_lite_slow_hash_v2(
        data: string): Array<boolean|string>;

    /**
     * CryptoNight Soft Shell v0 Slow Hash Method
     * 
     * @param data      hexadecimal string to hash
     * @param height    the height to use in the calculation
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_soft_shell_slow_hash_v0(
        data: string,
        height: number): Array<boolean|string>;

    /**
     * CryptoNight Soft Shell v1 Slow Hash Method
     * 
     * @param data      hexadecimal string to hash
     * @param height    the height to use in the calculation
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_soft_shell_slow_hash_v1(
        data: string,
        height: number): Array<boolean|string>;

    /**
     * CryptoNight Soft Shell v2 Slow Hash Method
     * 
     * @param data      hexadecimal string to hash
     * @param height    the height to use in the calculation
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function cn_soft_shell_slow_hash_v2(
        data: string,
        height: number): Array<boolean|string>;

    /**
     * Chukwa Slow Hash Method
     * 
     * @param data  hexadecimal string to hash
     * 
     * @returns {Array.<boolean|string>} array consisting of [error, hash]
     */
    export function chukwa_slow_hash(
        data: string): Array<boolean|string>;
}