export declare namespace Interfaces {
    /**
     * KeyPair object for holding privateKey and publicKey pairs
     */
    interface IKeyPair {
        /**
         * The private key
         */
        privateKey: string;
        /**
         * The public key
         */
        publicKey: string;
    }
    /**
     * A PreparedRingSignatures object for holding prepared signatures and the random scalar (k)
     */
    interface IPreparedRingSignatures {
        /**
         * The ring signatures
         */
        signatures: string[];
        /**
         * The random scalar key (k) for the signatures
         */
        key: string;
    }
}
/**
 * A class containing the TurtleCoin cryptographic primitive methods that wraps
 * the Node.js native module, the WASM binary, or native JS implementations
 * into a common interface
 */
export declare class Crypto {
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    static get type(): string;
    /**
     * Returns if the Node.js native library is being used
     */
    static get isNative(): boolean;
    /**
     * Returns if the wrapper is loaded and ready
     */
    static get isReady(): boolean;
    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    static set userCryptoFunctions(config: any);
    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives
     */
    static forceJSCrypto(): boolean;
    /**
     * Creates a new wrapper object
     * @param [config] may contain user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     */
    constructor(config?: any);
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    get type(): string;
    /**
     * Returns if the Node.js native library is being used
     */
    get isNative(): boolean;
    /**
     * Returns if the wrapper is loaded and ready
     */
    get isReady(): boolean;
    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    set userCryptoFunctions(config: any);
    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives
     */
    forceJSCrypto(): boolean;
    /**
     * Calculates the multisignature (m) private keys using our private spend key
     * and the public spend keys of other participants in a M:N scheme
     * @param privateSpendKey our private spend key
     * @param publicKeys an array of the other participants public spend keys
     */
    calculateMultisigPrivateKeys(privateSpendKey: string, publicKeys: string[]): string[];
    /**
     * Calculates a shared private key from the private keys supplied
     * @param privateKeys the array of private keys
     */
    calculateSharedPrivateKey(privateKeys: string[]): string;
    /**
     * Calculates a shared public key from the public keys supplied
     * @param publicKeys the array of public keys
     */
    calculateSharedPublicKey(publicKeys: string[]): string;
    /**
     * Checks whether a given key is a public key
     * @param key the public key to check
     */
    checkKey(key: string): boolean;
    /**
     * Checks a set of ring signatures to verify that they are valid
     * @param hash the hash (often the transaction prefix hash)
     * @param keyImage real keyImage used to generate the signatures
     * @param inputKeys the output keys used during signing (mixins + real)
     * @param signatures the signatures
     */
    checkRingSignature(hash: string, keyImage: string, inputKeys: string[], signatures: string[]): boolean;
    /**
     * Checks a set of ring signatures to verify that they are valid
     * @param hash the hash (often the transaction prefix hash)
     * @param keyImage real keyImage used to generate the signatures
     * @param inputKeys the output keys used during signing (mixins + real)
     * @param signatures the signatures
     */
    checkRingSignatures(hash: string, keyImage: string, inputKeys: string[], signatures: string[]): boolean;
    /**
     * Checks whether the given key is a private key
     * @param privateKey
     */
    checkScalar(privateKey: string): boolean;
    /**
     * Checks that the given signature is valid for the hash and public key supplied
     * @param hash the hash (message digest) used
     * @param publicKey the public key of the private key used to sign
     * @param signature the signature
     */
    checkSignature(hash: string, publicKey: string, signature: string): boolean;
    /**
     * Calculates the hash of the data supplied using the cn_fast_hash method
     * @param data
     */
    cn_fast_hash(data: string): string;
    /**
     * Completes a given set of prepared ring signatures using the single
     * privateEphemeral
     * @param privateEphemeral private ephemeral of the output being spent
     * @param realIndex the position of the signature in the array that belongs
     * to the real output being spent
     * @param k the random scalar provided with the prepared ring signatures
     * @param signatures the prepared ring signatures
     */
    completeRingSignatures(privateEphemeral: string, realIndex: number, k: string, signatures: string[]): string[];
    /**
     * Converts a key derivation to its resulting scalar
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     */
    derivationToScalar(derivation: string, outputIndex: number): string;
    /**
     * Derives the public ephemeral from the key derivation, output index, and
     * our public spend key
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     * @param publicKey our public spend key
     */
    derivePublicKey(derivation: string, outputIndex: number, publicKey: string): string;
    /**
     * Derives the private ephemeral from the key derivation, output index, and
     * our private spend key
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     * @param privateKey our private spend key
     */
    deriveSecretKey(derivation: string, outputIndex: number, privateKey: string): string;
    /**
     * Generates a set of deterministic spend keys for a sub wallet given
     * our root private spend key and the index of the subwallet
     * @param privateKey our root private spend key (seed)
     * @param walletIndex the index of the subwallet
     */
    generateDeterministicSubwalletKeys(privateKey: string, walletIndex: number): Interfaces.IKeyPair;
    /**
     * Generates a key derivation (aB) given the public key and private key
     * @param publicKey
     * @param privateKey
     */
    generateKeyDerivation(publicKey: string, privateKey: string): string;
    /**
     * Generates a key derivation scalar H_s(aB) given the public key and private key
     * @param publicKey the public key
     * @param privateKey the private key
     * @param outputIndex the output index
     */
    generateKeyDerivationScalar(publicKey: string, privateKey: string, outputIndex: number): string;
    /**
     * Generates a key image given the public ephemeral and the private ephemeral
     * @param publicEphemeral the public ephemeral of the output
     * @param privateEphemeral the private ephemeral of the output
     */
    generateKeyImage(publicEphemeral: string, privateEphemeral: string): string;
    /**
     * Generates a new random key pair
     */
    generateKeys(): Interfaces.IKeyPair;
    /**
     * Generates a partial signing key for a multisig ring signature set
     * @param signature the prepared real input signature
     * @param privateKey our private spend key (or multisig private key)
     */
    generatePartialSigningKey(signature: string, privateKey: string): string;
    /**
     * Generates a private view key from the private spend key
     * @param privateKey the private spend key
     */
    generatePrivateViewKeyFromPrivateSpendKey(privateKey: string): string;
    /**
     * Generates ring signatures for the supplied values
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param keyImage the key image of the output being spent
     * @param publicKeys an array of the output keys used for signing (mixins + our output)
     * @param privateEphemeral the private ephemeral of the output being spent
     * @param realIndex the array index of the real output being spent in the publicKeys array
     */
    generateRingSignatures(hash: string, keyImage: string, publicKeys: string[], privateEphemeral: string, realIndex: number): string[];
    /**
     * Generates a signature for the given message digest (hash)
     * @param hash the hash
     * @param publicKey the public key used in signing
     * @param privateKey the private key used to sign
     */
    generateSignature(hash: string, publicKey: string, privateKey: string): string;
    /**
     * Generates a vew key pair from the private spend key
     * @param privateKey the private spend key
     */
    generateViewKeysFromPrivateSpendKey(privateKey: string): Interfaces.IKeyPair;
    /**
     * Converts a hash to an elliptic curve point
     * @param hash the hash
     */
    hashToEllipticCurve(hash: string): string;
    /**
     * Converts a hash to a scalar
     * @param hash the hash
     */
    hashToScalar(hash: string): string;
    /**
     * Prepares ring signatures for completion or restoration later
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param keyImage the key image of the output being spent
     * @param publicKeys an array of the output keys used for signing (mixins + our output)
     * @param realIndex the array index of the real output being spent in the publicKeys array
     */
    prepareRingSignatures(hash: string, keyImage: string, publicKeys: string[], realIndex: number): Interfaces.IPreparedRingSignatures;
    /**
     * Re-initializes the underlying cryptographic primitives
     */
    reloadCrypto(): boolean;
    /**
     * Restores a key image from a set of partial key images generated by the other
     * participants in a multisig wallet
     * @param publicEphemeral the transaction public ephemeral
     * @param derivation the key derivation of the our output
     * @param outputIndex the index of our output in the transaction
     * @param partialKeyImages the array of partial key images from the needed
     * number of participants in the multisig scheme
     */
    restoreKeyImage(publicEphemeral: string, derivation: string, outputIndex: number, partialKeyImages: string[]): string;
    /**
     * Restores the ring signatures using the previously prepared ring signatures
     * and the necessary number of partial signing keys generated by other
     * participants in the multisig wallet
     * @param derivation the key derivation for the output being spent
     * @param outputIndex the index of the output being spent in the transaction
     * @param partialSigningKeys the array of partial signing keys from the necessary number
     * of participants
     * @param realIndex the index of the real input in the ring signatures
     * @param k the random scalar generated py preparing the ring signatures
     * @param signatures the prepared ring signatures
     */
    restoreRingSignatures(derivation: string, outputIndex: number, partialSigningKeys: string[], realIndex: number, k: string, signatures: string[]): string[];
    /**
     * Derives the public key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param publicKey the public key
     */
    scalarDerivePublicKey(derivationScalar: string, publicKey: string): string;
    /**
     * Derives the private key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param privateKey the private key
     */
    scalarDeriveSecretKey(derivationScalar: string, privateKey: string): string;
    /**
     * Multiplies two key images together
     * @param keyImageA
     * @param keyImageB
     */
    scalarmultKey(keyImageA: string, keyImageB: string): string;
    /**
     * Reduces a value to a scalar (mod q)
     * @param data
     */
    scReduce32(data: string): string;
    /**
     * Calculates the public key of a private key
     * @param privateKey
     */
    secretKeyToPublicKey(privateKey: string): string;
    /**
     * Calculates the merkle tree branch of the given hashes
     * @param hashes the array of hashes
     */
    tree_branch(hashes: string[]): string[];
    /**
     * Calculates the depth of the merkle tree
     * @param count the number of hashes in the tree
     */
    tree_depth(count: number): number;
    /**
     * Calculates the merkle tree hash of the given hashes
     * @param hashes the array of hashes
     */
    tree_hash(hashes: string[]): string;
    /**
     * Calculates the merkle tree hash from the given branch information
     * @param branches the merkle tree branches
     * @param leaf the leaf on the merkle tree
     * @param path the path on the merkle tree
     */
    tree_hash_from_branch(branches: string[], leaf: string, path: number): string;
    /**
     * Underives a public key instead of deriving it
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     * @param outputKey the output key in the transaction
     */
    underivePublicKey(derivation: string, outputIndex: number, outputKey: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v0 method
     * @param data
     */
    cn_slow_hash_v0(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v1 method
     * @param data
     */
    cn_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v2 method
     * @param data
     */
    cn_slow_hash_v2(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v0 method
     * @param data
     */
    cn_lite_slow_hash_v0(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v1 method
     * @param data
     */
    cn_lite_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v2 method
     * @param data
     */
    cn_lite_slow_hash_v2(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v0 method
     * @param data
     */
    cn_dark_slow_hash_v0(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v1 method
     * @param data
     */
    cn_dark_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v2 method
     * @param data
     */
    cn_dark_slow_hash_v2(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v0 method
     * @param data
     */
    cn_dark_lite_slow_hash_v0(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v1 method
     * @param data
     */
    cn_dark_lite_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v2 method
     * @param data
     */
    cn_dark_lite_slow_hash_v2(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v0 method
     * @param data
     */
    cn_turtle_slow_hash_v0(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v1 method
     * @param data
     */
    cn_turtle_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v2 method
     * @param data
     */
    cn_turtle_slow_hash_v2(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v0 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v0(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v1 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v2 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v2(data: string): string;
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v0 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v0(data: string, height: number): string;
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v1 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v1(data: string, height: number): string;
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v2 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v2(data: string, height: number): string;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash method
     * @param data
     * @param version
     */
    chukwa_slow_hash(data: string, version?: number): string;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_base method
     * @param data
     * @param iterations
     * @param memory
     * @param threads
     */
    chukwa_slow_hash_base(data: string, iterations: number, memory: number, threads: number): string;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v1 method
     * @param data
     */
    chukwa_slow_hash_v1(data: string): string;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v2 method
     * @param data
     */
    chukwa_slow_hash_v2(data: string): string;
}
