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

import * as bindings from 'bindings';
import {
    crypto_bulletproof_t,
    crypto_bulletproof_plus_t,
    crypto_borromean_signature_t,
    crypto_clsag_signature_t,
    IConfig,
    LibraryType,
    LibraryTypeName,
    ModuleSettings
} from './types';
import { Reader, Writer } from '@turtlecoin/bytestream';
import { format } from 'util';
import * as BigInteger from 'big-integer';
export {
    crypto_bulletproof_t,
    crypto_bulletproof_plus_t,
    crypto_borromean_signature_t,
    crypto_clsag_signature_t,
    IConfig,
    LibraryType
};

/**
 * @ignore
 */
const userConfig: IConfig = {};

/**
 * @ignore
 */
const runtime_configuration: ModuleSettings = {
    library: null,
    type: LibraryType.UNKNOWN
};

/**
 * A wrapper around the underlying cryptographic libraries offered by this package
 */
export default class Crypto {
    /**
     * Constructs a new instance of the class
     * @param config
     */
    constructor (config?: IConfig) {
        if (config) {
            Crypto.userConfig = config;
        }
    }

    /**
     * Retrieves the current user configuration
     */
    public static get userConfig (): IConfig {
        return userConfig;
    }

    /**
     * Sets the current user configuration
     * @param config
     */
    public static set userConfig (config: IConfig) {
        for (const key of Object.keys(config)) {
            userConfig[key] = config[key];
        }
    }

    /**
     * Sets the current user configuration
     * @param config
     */
    public set userConfig (config: IConfig) {
        Crypto.userConfig = config;
    }

    /**
     * Returns a human readable form of the underlying cryptographic module name
     */
    public static get library_name (): string {
        return LibraryTypeName(runtime_configuration.type);
    }

    /**
     * Returns the LibraryType of the underlying cryptographic module
     */
    public static get library_type (): LibraryType {
        return runtime_configuration.type;
    }

    /**
     * Returns if we are using the native node module for the underlying cryptographic module
     */
    public static get is_native (): boolean {
        return runtime_configuration.type === LibraryType.NODEADDON;
    }

    /**
     * Retrieves the current user configuration
     */
    public get userConfig (): IConfig {
        return userConfig;
    }

    /**
     * Returns a human readable form of the underlying cryptographic module name
     */
    public get library_name (): string {
        return LibraryTypeName(runtime_configuration.type);
    }

    /**
     * Returns the LibraryType of the underlying cryptographic module
     */
    public get library_type (): LibraryType {
        return runtime_configuration.type;
    }

    /**
     * Returns if we are using the native node module for the underlying cryptographic module
     */
    public get is_native (): boolean {
        return runtime_configuration.type === LibraryType.NODEADDON;
    }

    /**
     * Forces use of the Javascript asm.js library
     */
    public static async force_js_library (): Promise<boolean> {
        return Crypto.load_js();
    }

    /**
     * Forces use of the WASM library
     */
    public static async force_wasm_library (): Promise<boolean> {
        return Crypto.load_wasm();
    }

    private static async load_node_module (): Promise<boolean> {
        try {
            const module = bindings('crypto.node');

            if (Object.getOwnPropertyNames(module).length === 0 || typeof module.sha3 === 'undefined') {
                return false;
            }

            runtime_configuration.library = module;

            runtime_configuration.type = LibraryType.NODEADDON;

            return true;
        } catch (e) {
            return false;
        }
    }

    private static async load_wasm (): Promise<boolean> {
        const WASM = await (async () => {
            try {
                return require('../build.js/crypto-wasm');
            } catch {
                return null;
            }
        })();

        if (!WASM) {
            return false;
        }

        const module = await (new WASM());

        if (Object.getOwnPropertyNames(module).length === 0 || typeof module.sha3 === 'undefined') {
            return false;
        }

        runtime_configuration.library = module;

        runtime_configuration.type = LibraryType.WASMJS;

        return true;
    }

    private static async load_js (): Promise<boolean> {
        const JS = await (async () => {
            try {
                return require('../build.js/crypto-js');
            } catch {
                return null;
            }
        })();

        if (!JS) {
            return false;
        }

        const module = await (new JS());

        if (Object.getOwnPropertyNames(module).length === 0 || typeof module.sha3 === 'undefined') {
            return false;
        }

        runtime_configuration.library = module;

        runtime_configuration.type = LibraryType.JS;

        return true;
    }

    /**
     * Encodes the hexadecimal encoded string into a base58 encoded string
     * @param hex
     */
    public async base58_encode (hex: string): Promise<string> {
        return execute('base58_encode', hex);
    }

    /**
     * Encodes the hexadecimal encoded string into a base58 encoded string
     * and automatically includes a SHA3 checksum in the result
     * @param hex
     */
    public async base58_encode_check (hex: string): Promise<string> {
        return execute('base58_encode_check', hex);
    }

    /**
     * Decodes the Base58 encoded string into a hexadecimal encoded string
     * @param base58
     */
    public async base58_decode (base58: string): Promise<string> {
        return execute('base58_decode', base58);
    }

    /**
     * Decodes the Base58 encoded string into a hexadecimal encoded string
     * as long as the checksum included matches the checksum expected
     * @param base58
     */
    public async base58_decode_check (base58: string): Promise<string> {
        return execute('base58_decode_check', base58);
    }

    /**
     * Encodes the hexadecimal encoded string into a CryptoNote base58 encoded string
     * @param hex
     */
    public async cn_base58_encode (hex: string): Promise<string> {
        return execute('cn_base58_encode', hex);
    }

    /**
     * Encodes the hexadecimal encoded string into a CryptoNote base58 encoded string
     * and automatically includes a SHA3 checksum in the result
     * @param hex
     */
    public async cn_base58_encode_check (hex: string): Promise<string> {
        return execute('cn_base58_encode_check', hex);
    }

    /**
     * Decodes the CryptoNote Base58 encoded string into a hexadecimal encoded string
     * @param base58
     */
    public async cn_base58_decode (base58: string): Promise<string> {
        return execute('cn_base58_decode', base58);
    }

    /**
     * Decodes the CryptoNote Base58 encoded string into a hexadecimal encoded string
     * as long as the checksum included matches the checksum expected
     * @param base58
     */
    public async cn_base58_decode_check (base58: string): Promise<string> {
        return execute('cn_base58_decode_check', base58);
    }

    /**
     * Checks that the provided ring signature is valid
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     */
    public async borromean_check_ring_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        signature: crypto_borromean_signature_t
    ): Promise<boolean> {
        const sig = JSON.stringify(signature);

        return execute('borromean_check_ring_signature', message_digest, key_image, public_keys, sig);
    }

    /**
     * Completes the ring signature using the provided values
     * @param signing_scalar
     * @param real_output_index
     * @param signature
     * @param partial_signing_scalars
     */
    public async borromean_complete_ring_signature (
        signing_scalar: string,
        real_output_index: number,
        signature: crypto_borromean_signature_t,
        partial_signing_scalars: string[] = []
    ): Promise<crypto_borromean_signature_t> {
        const sig = JSON.stringify(signature);

        const result = await execute('borromean_complete_ring_signature', signing_scalar,
            real_output_index, sig, partial_signing_scalars);

        return JSON.parse(result);
    }

    /**
     * Generates a partial signing scalar for the provided values (Multisig)
     * @param real_output_index
     * @param signature
     * @param secret_spend_key
     */
    public async borromean_generate_partial_signing_scalar (
        real_output_index: number,
        signature: crypto_borromean_signature_t,
        secret_spend_key: string
    ): Promise<string> {
        const sig = JSON.stringify(signature);

        return execute('borromean_generate_partial_signing_scalar', real_output_index,
            sig, secret_spend_key);
    }

    /**
     * Generates a ring signature for the provided values
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     */
    public async borromean_generate_ring_signature (
        message_digest: string,
        secret_ephemeral: string,
        public_keys: string[]
    ): Promise<crypto_borromean_signature_t> {
        const result = await execute('borromean_generate_ring_signature', message_digest, secret_ephemeral,
            public_keys);

        return JSON.parse(result);
    }

    /**
     * Prepares a ring signature for the provided values
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     */
    public async borromean_prepare_ring_signature (
        message_digest: string, key_image: string,
        public_keys: string[], real_output_index: number): Promise<crypto_borromean_signature_t> {
        const result = await execute('borromean_prepare_ring_signature', message_digest, key_image,
            public_keys, real_output_index);

        return JSON.parse(result);
    }

    /**
     * Generates the proof and commitments for the provided values
     * @param amounts
     * @param blinding_factors
     */
    public async bulletproofs_prove (
        amounts: number[], blinding_factors: string[]): Promise<[crypto_bulletproof_t, string[]]> {
        const [proof, commitments] = await execute('bulletproofs_prove', amounts, blinding_factors);

        return [JSON.parse(proof), commitments];
    }

    /**
     * Verifies the proofs for the provided commitments
     * @param proofs
     * @param commitments
     */
    public async bulletproofs_verify (
        proofs: crypto_bulletproof_t[], commitments: string[][]): Promise<boolean> {
        const proofs_array = JSON.stringify(proofs);

        return execute('bulletproofs_verify', proofs_array, commitments);
    }

    /**
     * Generates the proof and commitments for the provided values
     * @param amounts
     * @param blinding_factors
     */
    public async bulletproofsplus_prove (
        amounts: number[], blinding_factors: string[]): Promise<[crypto_bulletproof_plus_t, string[]]> {
        const [proof, commitments] = await execute('bulletproofsplus_prove', amounts, blinding_factors);

        return [JSON.parse(proof), commitments];
    }

    /**
     * Verifies the proofs for the provided commitments
     * @param proofs
     * @param commitments
     */
    public async bulletproofsplus_verify (
        proofs: crypto_bulletproof_plus_t[], commitments: string[][]): Promise<boolean> {
        const proofs_array = JSON.stringify(proofs);

        return execute('bulletproofsplus_verify', proofs_array, commitments);
    }

    /**
     * Checks that the provided ring signature is valid
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     * @param commitments
     * @param pseudo_commitment
     */
    public async clsag_check_ring_signature (message_digest: string, key_image: string, public_keys: string[],
        signature: crypto_clsag_signature_t, commitments: string[] = []
    ): Promise<boolean> {
        const sig = JSON.stringify(signature);

        return execute('clsag_check_ring_signature', message_digest, key_image,
            public_keys, sig, commitments);
    }

    /**
     * Completes the ring signature using the provided values
     * @param signing_scalar
     * @param real_output_index
     * @param signature
     * @param h
     * @param mu_P
     * @param partial_signing_scalars
     */
    public async clsag_complete_ring_signature (signing_scalar: string, real_output_index: number,
        signature: crypto_clsag_signature_t, h: string[],
        mu_P: string, partial_signing_scalars: string[] = []): Promise<crypto_clsag_signature_t> {
        const sig = JSON.stringify(signature);

        const result = await execute('clsag_complete_ring_signature',
            signing_scalar, real_output_index, sig, h, mu_P, partial_signing_scalars);

        return JSON.parse(result);
    }

    /**
     * Generates a partial signing scalar for the provided values (Multisig)
     * @param mu_P
     * @param secret_spend_key
     */
    public async clsag_generate_partial_signing_scalar (
        mu_P: string, secret_spend_key: string): Promise<string> {
        return execute('clsag_generate_partial_signing_scalar', mu_P, secret_spend_key);
    }

    /**
     * Generates a ring signature for the provided values
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     */
    public async clsag_generate_ring_signature (message_digest: string, secret_ephemeral: string,
        public_keys: string[], input_blinding_factor: string = '',
        public_commitments: string[] = [], pseudo_blinding_factor: string = '',
        pseudo_commitment: string = ''): Promise<crypto_clsag_signature_t> {
        const result = await execute('clsag_generate_ring_signature',
            message_digest,
            secret_ephemeral,
            public_keys,
            input_blinding_factor,
            public_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);

        return JSON.parse(result);
    }

    /**
     * Prepares a ring signature for the provided values
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     */
    public async clsag_prepare_ring_signature (message_digest: string, key_image: string, public_keys: string[],
        real_output_index: number,
        input_blinding_factor: string = '', public_commitments: string[] = [],
        pseudo_blinding_factor: string = '', pseudo_commitment: string = ''
    ): Promise<[crypto_clsag_signature_t, string[], string]> {
        const [signature, h, mu_P] = await execute('clsag_prepare_ring_signature',
            message_digest,
            key_image,
            public_keys,
            real_output_index,
            input_blinding_factor,
            public_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);

        return [JSON.parse(signature), h, mu_P];
    }

    /**
     * Calculates the H() of the provided value
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     */
    public async argon2d (
        input: string, iterations: number = 1, memory: number = 256, threads: number = 1): Promise<string> {
        return execute('argon2d', input, iterations, memory, threads);
    }

    /**
     * Calculates the H() of the provided value
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     */
    public async argon2i (
        input: string, iterations: number = 1, memory: number = 256, threads: number = 1): Promise<string> {
        return execute('argon2i', input, iterations, memory, threads);
    }

    /**
     * Calculates the H() of the provided value
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     */
    public async argon2id (
        input: string, iterations: number = 1, memory: number = 256, threads: number = 1): Promise<string> {
        return execute('argon2id', input, iterations, memory, threads);
    }

    /**
     * Calculates the H() of the provided value
     * @param input
     */
    public async sha3 (input: string): Promise<string> {
        return execute('sha3', input);
    }

    /**
     * Calculates the H_i() of the provided value over specified stretching iterations
     * @param input
     * @param iterations
     */
    public async sha3_slow_hash (input: string, iterations: number = 0): Promise<string> {
        return execute('sha3_slow_hash', input, iterations);
    }

    /**
     * Calculates the Merkle root for the provided values
     * @param hashes
     */
    public async root_hash (hashes: string[]): Promise<string> {
        return execute('root_hash', hashes);
    }

    /**
     * Calculates the Merkle root for the provided values
     * @param branches
     * @param depth
     * @param leaf
     * @param path
     */
    public async root_hash_from_branch (
        branches: string[], depth: number, leaf: string, path: number): Promise<string> {
        return execute('root_hash_from_branch', branches, depth, leaf, path);
    }

    /**
     * Calculates the tree branch of the provided values
     * @param hashes
     */
    public async tree_branch (hashes: string[]): Promise<string[]> {
        return execute('tree_branch', hashes);
    }

    /**
     * Calculates the depth of the merkle tree for the given count of values
     * @param count
     */
    public async tree_depth (count: number): Promise<number> {
        return execute('tree_depth', count);
    }

    /**
     * Calculates the checksum index position in the word list for the given set of words
     * @param words
     */
    public async mnemonics_calculate_checksum_index (words: string[]): Promise<number> {
        return execute('mnemonics_calculate_checksum_index', words);
    }

    /**
     * Decodes a vector of mnemonic phrase words into the seed it represents
     * @param words
     * @returns [seed, timestamp]
     */
    public async mnemonics_decode (words: string[]): Promise<[string, BigInteger.BigInteger]> {
        const [seed, timestamp] = await execute('mnemonics_decode', words);

        const reader = new Reader(timestamp);

        return [seed, reader.uint64_t()];
    }

    /**
     * Encodes the given seed into a vector of mnemonic phrase words
     * @param seed
     * @param timestamp
     * @param auto_timestamp
     */
    public async mnemonics_encode (
        seed: string,
        timestamp: number | BigInteger.BigInteger = 0,
        auto_timestamp = true
    ): Promise<string[]> {
        const writer = new Writer();

        writer.uint64_t(timestamp);

        return execute('mnemonics_encode', seed, writer.blob, (auto_timestamp) ? 1 : 0);
    }

    /**
     * Finds the index of the given word in the word list or returns -1 if not found
     * @param word
     */
    public async mnemonics_word_index (word: string): Promise<number> {
        return execute('mnemonics_word_index', word);
    }

    /**
     * Returns the full word list
     */
    public async mnemonics_word_list (): Promise<string[]> {
        return execute('mnemonics_word_list');
    }

    /**
     * Returns the full word list but trimmed to the minimum number of characters per word
     */
    public async mnemonics_word_list_trimmed (): Promise<string[]> {
        return execute('mnemonics_word_list_trimmed');
    }

    /**
     * Generates the multisig secret key for the provided values
     * @param their_public_key
     * @param our_secret_key
     */
    public async generate_multisig_secret_key (
        their_public_key: string, our_secret_key: string): Promise<string> {
        return execute('generate_multisig_secret_key', their_public_key, our_secret_key);
    }

    /**
     * Generate the multisig secret keys for the provided values
     * @param their_public_keys
     * @param our_secret_key
     */
    public async generate_multisig_secret_keys (
        their_public_keys: string[], our_secret_key: string): Promise<string[]> {
        return execute('generate_multisig_secret_keys', their_public_keys, our_secret_key);
    }

    /**
     * Calculate the shared public key for the provided values
     * @param public_keys
     */
    public async generate_shared_public_key (public_keys: string[]): Promise<string> {
        return execute('generate_shared_public_key', public_keys);
    }

    /**
     * Calculate the shared secret key for the provided values
     * @param secret_keys
     */
    public async generate_shared_secret_key (secret_keys: string[]): Promise<string> {
        return execute('generate_shared_secret_key', secret_keys);
    }

    /**
     * Calculates the number of multisig key exchange rounds required for the provided values
     * @param participants
     * @param threshold
     */
    public async rounds_required (participants: number, threshold: number): Promise<number> {
        return execute('rounds_required', participants, threshold);
    }

    /**
     * Checks to verify that the total value of the pseudo commitments is equal to the total value
     * of the output_commitments plus the transaction fee
     * @param pseudo_commitments
     * @param output_commitments
     * @param transaction_fee
     */
    public async check_commitments_parity (
        pseudo_commitments: string[], output_commitments: string[], transaction_fee: number): Promise<boolean> {
        return execute('check_commitments_parity', pseudo_commitments, output_commitments, transaction_fee);
    }

    /**
     * Generates the amount mask for the provided value
     * @param derivation_scalar
     */
    public async generate_amount_mask (derivation_scalar: string): Promise<string> {
        return execute('generate_amount_mask', derivation_scalar);
    }

    /**
     * Generates the blinding factor for the provided value
     * @param derivation_scalar
     */
    public async generate_commitment_blinding_factor (derivation_scalar: string): Promise<string> {
        return execute('generate_commitment_blinding_factor', derivation_scalar);
    }

    /**
     * Generates a pedersen commitment for the provided values
     * @param blinding_factor
     * @param amount
     */
    public async generate_pedersen_commitment (blinding_factor: string, amount: number): Promise<string> {
        return execute('generate_pedersen_commitment', blinding_factor, amount);
    }

    /**
     * Generates pseudo pedersen commitments for the provided values
     * @param input_amounts
     * @param output_blinding_factors
     */
    public async generate_pseudo_commitments (
        input_amounts: number[], output_blinding_factors: string[]): Promise<[string[], string[]]> {
        return execute('generate_pseudo_commitments', input_amounts, output_blinding_factors);
    }

    /**
     * Generates a pedersen commitment for the provided value
     * @param amount
     */
    public async generate_transaction_fee_commitment (amount: number): Promise<string> {
        return execute('generate_pedersen_commitment', ''.padEnd(64, '0'), amount);
    }

    /**
     * Hides/Un-Hides an amount using the provided mask
     * @param amount_mask
     * @param amount
     */
    public async toggle_masked_amount (
        amount_mask: string, amount: string | number | BigInteger.BigInteger): Promise<BigInteger.BigInteger> {
        if (typeof amount !== 'string') {
            const writer = new Writer();

            writer.uint64_t(amount);

            amount = writer.blob;
        } else {
            const reader = new Reader(amount);

            try {
                reader.uint64_t();
            } catch {
                throw new Error('Cannot read amount value');
            }
        }

        return execute('toggle_masked_amount', amount_mask, amount)
            .then(result => {
                const reader = new Reader(result);

                return reader.uint64_t();
            });
    }

    /**
     * Checks that the provided signature is valid
     * @param message_digest
     * @param public_key
     * @param signature
     */
    public async check_signature (
        message_digest: string, public_key: string, signature: string): Promise<boolean> {
        return execute('check_signature', message_digest, public_key, signature);
    }

    /**
     * Completes the signature using the provided values
     * @param signing_scalar
     * @param signature
     * @param partial_signing_scalars
     */
    public async complete_signature (
        signing_scalar: string | undefined, signature: string, partial_signing_scalars: string[] = []
    ): Promise<string> {
        if (!signing_scalar) {
            signing_scalar = ''.padStart(64, '0');
        }

        return execute('complete_signature', signing_scalar, signature, partial_signing_scalars);
    }

    /**
     * Generates a partial signing scalar for the provided values (Multisig)
     * @param signature
     * @param secret_spend_key
     */
    public generate_partial_signing_scalar (signature: string, secret_spend_key: string): Promise<string> {
        return execute('generate_partial_signing_scalar', signature, secret_spend_key);
    }

    /**
     * Generates a signature for the provided values
     * @param message_digest
     * @param secret_key
     */
    public generate_signature (message_digest: string, secret_key: string): Promise<string> {
        return execute('generate_signature', message_digest, secret_key);
    }

    /**
     * Prepares a signature for the provided values
     * @param message_digest
     * @param public_key
     */
    public prepare_signature (message_digest: string, public_key: string): Promise<string> {
        return execute('prepare_signature', message_digest, public_key);
    }

    /**
     * Forces use of the Javascript asm.js library
     */
    public async force_js_library (): Promise<boolean> {
        return Crypto.load_js();
    }

    /**
     * Forces use of the WASM library
     */
    public async force_wasm_library (): Promise<boolean> {
        return Crypto.load_wasm();
    }

    /**
     * Initializes the underlying cryptographic library via auto-detection (fastest to slowest)
     */
    public async initialize (): Promise<boolean> {
        if (runtime_configuration.library == null) {
            if (await Crypto.load_node_module()) {
                return true;
            }

            if (await Crypto.load_wasm()) {
                return true;
            }

            return await Crypto.load_js();
        }

        return true;
    }

    /**
     * Calculates the exponent of 2^e that matches the target value
     * @param value
     */
    public async calculate_base2_exponent (value: number): Promise<number> {
        return execute('calculate_base2_exponent', value);
    }

    /**
     * Checks the given value to verify if it is a point on the curve
     * @param point
     */
    public async check_point (point: string): Promise<boolean> {
        return execute('check_point', point);
    }

    /**
     * Checks the given value to verify that it is a scalar value
     * @param scalar
     */
    public async check_scalar (scalar: string): Promise<boolean> {
        return execute('check_scalar', scalar);
    }

    /**
     * Computes a derivation scalar for the given values
     * @param derivation
     * @param output_index
     */
    public async derivation_to_scalar (derivation: string, output_index: number): Promise<string> {
        return execute('derivation_to_scalar', derivation, output_index);
    }

    /**
     * Computes the public key for the given values
     * @param derivation_scalar
     * @param public_key
     */
    public async derive_public_key (derivation_scalar: string, public_key: string): Promise<string> {
        return execute('derive_public_key', derivation_scalar, public_key);
    }

    /**
     * Computes the secret key for the given values
     * @param derivation_scalar
     * @param secret_key
     */
    public async derive_secret_key (derivation_scalar: string, secret_key: string): Promise<string> {
        return execute('derive_secret_key', derivation_scalar, secret_key);
    }

    /**
     * Generates a key derivation for the given values
     * @param public_key
     * @param secret_key
     */
    public async generate_key_derivation (public_key: string, secret_key: string): Promise<string> {
        return execute('generate_key_derivation', public_key, secret_key);
    }

    /**
     * Generates a key image for the given values
     * @param public_emphemeral
     * @param secret_ephemeral
     * @param partial_key_images
     */
    public async generate_key_image (
        public_emphemeral: string, secret_ephemeral: string, partial_key_images: string[] = []): Promise<string> {
        return execute('generate_key_image', public_emphemeral, secret_ephemeral, partial_key_images);
    }

    /**
     * Generates a v2 key image for the given value
     * @param secret_ephemeral
     */
    public async generate_key_image_v2 (secret_ephemeral: string): Promise<string> {
        return execute('generate_key_image_v2', secret_ephemeral);
    }

    /**
     * Generates a new random key pair
     */
    public async generate_keys (): Promise<[string, string]> {
        return execute('generate_keys');
    }

    /**
     * Generates a new wallet seed and uses the provided additional entropy if provided
     *
     * @param entropy
     */
    public async generate_wallet_seed (entropy = ''): Promise<[string, string[], BigInteger.BigInteger]> {
        entropy = Buffer.from(entropy).toString('hex');

        const [seed, words, timestamp] = await execute('generate_wallet_seed', entropy);

        const reader = new Reader(timestamp);

        return [seed, words, reader.uint64_t()];
    }

    /**
     * Generates deterministic subwallet keys from the wallet seed value.
     *
     * For compatibility & security purposes, all wallet keys and addresses, should be derived from
     * the wallet seed and the seed should never be used directly.
     *
     * Subwallets are generated by injecting deterministic salt into the hashing process
     * whereby it is nearly impossible to reconstruct the spend keys without knowing the
     * subwallet index and the seed value that they were derived from.
     *
     * @param wallet_seed
     * @param subwallet_index
     */
    public async generate_wallet_spend_keys (
        wallet_seed: string, subwallet_index: number = 0): Promise<[string, string]> {
        return execute('generate_wallet_spend_keys', wallet_seed, subwallet_index);
    }

    /**
     * Calculates deterministic wallet view keys from the given wallet seed value.
     *
     * For compatibility & security purposes, all wallet keys and addresses, should be derived from
     * the wallet seed and the seed should never be used directly.
     *
     * @param wallet_seed
     */
    public async generate_wallet_view_keys (wallet_seed: string): Promise<[string, string]> {
        return execute('generate_wallet_view_keys', wallet_seed);
    }

    /**
     * Calculates Hp() for the given value
     * @param input
     */
    public async hash_to_point (input: string): Promise<string> {
        return execute('hash_to_point', input);
    }

    /**
     * Calculates Hs() for the given value
     * @param input
     */
    public async hash_to_scalar (input: string): Promise<string> {
        return execute('hash_to_scalar', input);
    }

    /**
     * Rounds the value to the next power of 2 (2^n)
     * @param value
     */
    public async pow2_round (value: number): Promise<number> {
        return execute('pow2_round', value);
    }

    /**
     * Generates a random hash
     */
    public async random_hash (): Promise<string> {
        return execute('random_hash');
    }

    /**
     * Generates an array of random hashes
     * @param count
     */
    public async random_hashes (count: number = 1): Promise<string[]> {
        return execute('random_hashes', count);
    }

    /**
     * Generates a random point on the curve
     */
    public async random_point (): Promise<string> {
        return execute('random_point');
    }

    /**
     * Generates an array of random points on the curve
     * @param count
     */
    public async random_points (count: number = 1): Promise<string[]> {
        return execute('random_points', count);
    }

    /**
     * Generates a random scalar value
     */
    public async random_scalar (): Promise<string> {
        return execute('random_scalar');
    }

    /**
     * Generates an array of random scalar values
     * @param count
     */
    public async random_scalars (count: number = 1): Promise<string[]> {
        return execute('random_scalars', count);
    }

    /**
     * Calculates the public key for the given secret key
     * @param secret_key
     */
    public async secret_key_to_public_key (secret_key: string): Promise<string> {
        return execute('secret_key_to_public_key', secret_key);
    }

    /**
     * Calculates the public key from the provided values
     * @param derivation
     * @param output_index
     * @param public_ephemeral
     */
    public async underive_public_key (
        derivation: string, output_index: number, public_ephemeral: string): Promise<string> {
        return execute('underive_public_key', derivation, output_index, public_ephemeral);
    }
}

/**
 * @ignore
 */
async function execute (...args: any[]): Promise<any> {
    const method: string = args.shift();

    const is_our_module = (): boolean => {
        switch (runtime_configuration.type) {
            case LibraryType.WASMJS:
            case LibraryType.JS:
            case LibraryType.NODEADDON:
                return true;
            default:
                return false;
        }
    };

    const exchange_json = (): boolean => {
        switch (runtime_configuration.type) {
            case LibraryType.WASMJS:
            case LibraryType.JS:
                return true;
            default:
                return false;
        }
    };

    const method_call = (() => {
        if (typeof runtime_configuration.library[method] !== 'undefined') {
            return runtime_configuration.library[method];
        }

        return undefined;
    })();

    const args_to_obj = (parameters: any[]): string => {
        const obj: any = {};

        for (let i = 0; i < parameters.length; ++i) {
            obj[i.toString()] = parameters[i];
        }

        return JSON.stringify(obj);
    };

    return new Promise((resolve, reject) => {
        if (userConfig[method]) {
            try {
                return resolve(userConfig[method](...args));
            } catch (e) {
                return reject(new Error(format('Could not call user configured primitive: %', e.toString())));
            }
        } else if (is_our_module() && method_call) {
            try {
                const temp_result: any =
                    exchange_json() ? method_call(args_to_obj(args)) : method_call(...args);

                const result: any = exchange_json() ? JSON.parse(temp_result) : temp_result;

                if (typeof result === 'boolean') {
                    return resolve(result);
                } else if (Array.isArray(result)) {
                    const failure: boolean = result.shift();

                    if (result.length === 0) {
                        return resolve(failure);
                    }

                    if (failure) {
                        const error = format('0x03: %s(%s) => [%s]', method,
                            exchange_json() ? args_to_obj(args) : args.join(','), result.join(','));

                        return reject(new Error(error));
                    }

                    if (result.length === 1) {
                        return resolve(result[0]);
                    }

                    return resolve(result);
                }

                const error = format('0x04: %s(%s): %s', method,
                    exchange_json() ? args_to_obj(args) : args.join(','), result);

                return reject(new Error(error));
            } catch (e) {
                /**
                 * If we threw an error on a check/verify method, then it is very likely
                 * because we were supplied with invalid values that cannot be caught
                 * by an emscripten build without enabling exception catching
                 */
                if (method.indexOf('check') !== -1 || method.indexOf('verify') !== -1) {
                    return resolve(false);
                }

                const error = format('0x02: %s(%s): %s', method,
                    exchange_json() ? args_to_obj(args) : args.join(','), e.toString());

                return reject(new Error(error));
            }
        } else {
            const error = format('0x01: Method Not Found. %s(%s)', method, args.join(','));

            return reject(new Error(error));
        }
    });
}
