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

import * as BigInteger from 'big-integer';

/**
 * Specifies the known library types
 */
export enum LibraryType {
    UNKNOWN,
    NODEADDON,
    WASMJS,
    JS
}

/**
 * @ignore
 */
export function LibraryTypeName (type: LibraryType): string {
    switch (type) {
        case LibraryType.NODEADDON:
            return 'node c++ addon';
        case LibraryType.WASMJS:
            return 'wasm.js library';
        case LibraryType.JS:
            return 'javascript asm.js (slow)';
        default:
            return 'unknown';
    }
}

/**
 * @ignore
 */
export interface ModuleSettings {
    library: any;
    type: LibraryType;
}

/**
 * Represents a Bulletproof proof
 */
export interface crypto_bulletproof_t {
    A: string;
    S: string;
    T1: string;
    T2: string;
    taux: string;
    mu: string;
    L: string[];
    R: string[];
    g: string;
    h: string;
    t: string;
}

/**
 * Represents a Bulletproof+ proof
 */
export interface crypto_bulletproof_plus_t {
    A: string;
    A1: string;
    B: string;
    r1: string;
    s1: string;
    d1: string;
    L: string[];
    R: string[];
}

/**
 * Represents a CLSAG signature
 */
export interface crypto_clsag_signature_t {
    scalars: string[];
    challenge: string;
    commitment_image?: string;
}

/**
 * Defines all of the user overrideable crypto methods
 */
export interface IConfig {
    base58_encode?: (hex: string) => Promise<string>;
    base58_encode_check?: (hex: string) => Promise<string>;
    base58_decode?: (base58: string) => Promise<string>;
    base58_decode_check?: (base58: string) => Promise<string>;

    cn_base58_encode?: (hex: string) => Promise<string>;
    cn_base58_encode_check?: (hex: string) => Promise<string>;
    cn_base58_decode?: (base58: string) => Promise<string>;
    cn_base58_decode_check?: (base58: string) => Promise<string>;

    borromean_check_ring_signature?:
        (message_digest: string, key_image: string, public_keys: string[], signature: string[]) => Promise<boolean>;
    borromean_complete_ring_signature?:
        (signing_scalar: string, real_output_index: number, signature: string[],
         partial_signing_scalars: string[]) => Promise<string[]>;
    borromean_generate_partial_signing_scalar?:
        (real_output_index: number, signature: string[], secret_spend_key: string) => Promise<string>;
    borromean_generate_ring_signature?:
        (message_digest: string, secret_ephemeral: string, public_keys: string[]) => Promise<string[]>;
    borromean_prepare_ring_signature?:
        (message_digest: string, key_image: string, public_keys: string[], real_output_index: number
        ) => Promise<string[]>;

    bulletproofs_prove?: (amounts: number[], blinding_factors: string[]) => Promise<[crypto_bulletproof_t, string[]]>;
    bulletproofs_verify?: (proofs: crypto_bulletproof_t[], commitments: string[][]) => Promise<boolean>;

    bulletproofsplus_prove?:
        (amounts: number[], blinding_factors: string[]) => Promise<[crypto_bulletproof_plus_t, string[]]>;
    bulletproofsplus_verify?: (proofs: crypto_bulletproof_plus_t[], commitments: string[][]) => Promise<boolean>;

    clsag_check_ring_signature?:
        (message_digest: string, key_image: string, public_keys: string[], signature: crypto_clsag_signature_t,
         commitments: string[], pseudo_commitment: string) => Promise<boolean>;
    clsag_complete_ring_signature?:
        (signing_scalar: string, real_output_index: number, signature: crypto_clsag_signature_t,
         h: string[], mu_P: string, partial_signing_scalars: string[]) => Promise<crypto_clsag_signature_t>;
    clsag_generate_partial_signing_scalar?: (mu_P: string, secret_spend_key: string) => Promise<string>;
    clsag_generate_ring_signature?:
        (message_digest: string, secret_ephemeral: string, public_keys: string[],
         input_blinding_factor: string, public_commitments: string[],
         pseudo_blinding_factor: string, pseudo_commitment: string) => Promise<crypto_clsag_signature_t>;
    clsag_prepare_ring_signature?:
        (message_digest: string, key_image: string, public_keys: string[], real_output_index: number,
         input_blinding_factor: string, public_commitments: string[],
         pseudo_blinding_factor: string, pseudo_commitment: string
        ) => Promise<[crypto_clsag_signature_t, string[], string]>;

    argon2d?: (input: string, iterations: number, memory: number, threads: number) => Promise<string>;
    argon2i?: (input: string, iterations: number, memory: number, threads: number) => Promise<string>;
    argon2id?: (input: string, iterations: number, memory: number, threads: number) => Promise<string>;
    sha3?: (input: string) => Promise<string>;
    sha3_slow_hash?: (input: string, iterations: number) => Promise<string>;
    root_hash?: (hashes: string[]) => Promise<string>;
    root_hash_from_branch?: (branches: string[], depth: number, leaf: string, path: number) => Promise<string>;
    tree_branch?: (hashes: string[]) => Promise<string[]>;
    tree_depth?: (count: number) => Promise<number>;

    generate_multisig_secret_key?: (their_public_key: string, our_secret_key: string) => Promise<string>;
    generate_multisig_secret_keys?: (their_public_keys: string[], our_secret_key: string) => Promise<string[]>;
    generate_shared_public_key?: (public_keys: string[]) => Promise<string>;
    generate_shared_secret_key?: (secret_keys: string[]) => Promise<string>;
    rounds_required?: (participants: number, threshold: number) => Promise<number>;

    mnemonics_calculate_checksum_index?: (words: string[]) => Promise<number>;
    mnemonics_decode?: (words: string[]) => Promise<[string, BigInteger.BigInteger]>;
    mnemonics_encode?:
        (seed: string, timestamp: number | BigInteger.BigInteger, auto_timestamp: boolean) => Promise<string[]>;
    mnemonics_word_index?: (word: string) => Promise<number>;
    mnemonics_word_list?: () => Promise<string[]>;
    mnemonics_word_list_trimmed?: () => Promise<string[]>;

    check_commitments_parity?:
        (pseudo_commitments: string[], output_commitments: string[], transaction_fee: number) => Promise<boolean>;
    generate_amount_mask?:
        (derivation_scalar: string) => Promise<string>;
    generate_commitment_blinding_factor?: (derivation_scalar: string) => Promise<string>;
    generate_pedersen_commitment?: (blinding_factor: string, amount: number) => Promise<string>;
    generate_pseudo_commitments?:
        (input_amounts: number[], output_blinding_factors: string[]) => Promise<[string[], string[]]>
    generate_transaction_fee_commitment?: (amount: number) => Promise<string>;
    toggle_masked_amount?:
        (amount_mask: string, amount: string | number | BigInteger.BigInteger) => Promise<BigInteger.BigInteger>;

    check_signature?: (message_digest: string, public_key: string, signature: string) => Promise<boolean>;
    complete_signature?:
        (signing_scalar: string | undefined, signature: string, partial_signing_scalars: string[]) => Promise<string>;
    generate_partial_signing_scalar?: (signature: string, secret_spend_key: string) => Promise<string>;
    generate_signature?: (message_digest: string, secret_key: string) => Promise<string>;
    prepare_signature?: (message_digest: string, public_key: string) => Promise<string>;

    calculate_base2_exponent?: (value: number) => Promise<number>;
    check_point?: (point: string) => Promise<boolean>;
    check_scalar?: (scalar: string) => Promise<boolean>;
    derivation_to_scalar?: (derivation: string, output_index: number) => Promise<string>;
    derive_public_key?: (derivation_scalar: string, public_key: string) => Promise<string>;
    derive_secret_key?: (derivation_scalar: string, secret_key: string) => Promise<string>;
    generate_key_derivation?: (public_key: string, secret_key: string) => Promise<string>;
    generate_key_image?:
        (public_ephemeral: string, secret_ephemeral: string, partial_key_images: string[]) => Promise<string>;
    generate_key_image_v2?: (secret_ephemeral: string) => Promise<string>;
    generate_keys?: () => Promise<[string, string]>;
    generate_wallet_spend_keys?: (secret_spend_key: string, subwallet_index: number) => Promise<[string, string]>;
    generate_wallet_view_keys?: (secret_spend_key: string) => Promise<[string, string]>;
    hash_to_point?: (input: string) => Promise<string>;
    hash_to_scalar?: (input: string) => Promise<string>;
    pow2_round?: (value: number) => Promise<number>;
    random_point?: () => Promise<string>;
    random_points?: (count: number) => Promise<string[]>;
    random_scalar?: () => Promise<string>;
    random_scalars?: (count: number) => Promise<string[]>;
    secret_key_to_public_key?: (secret_key: string) => Promise<string>;
    underive_public_key?: (derivation: string, output_index: number, public_ephemeral: string) => Promise<string>;

    [key: string]: any;
}
