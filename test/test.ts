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

import Crypto, { crypto_bulletproof_plus_t, crypto_bulletproof_t } from '../typescript';
import { describe, it, before } from 'mocha';
import * as assert from 'assert';
import { sha3_256 } from 'js-sha3';
import * as BigInteger from 'big-integer';

interface KeyPair {
    secret: string;
    public: string;
}

interface Participant {
    spend: KeyPair;
    view: KeyPair;
    multisig: {
        secrets: string[];
        publics: string[];
    }
}

describe('Cryptographic Tests', async () => {
    let crypto: Crypto;
    let wallet_seed: string;

    before(async () => {
        crypto = new Crypto();

        await crypto.initialize();

        if (process.env.FORCE_JS) {
            if (await Crypto.force_js_library()) {
                console.warn('Performing tests with Javascript Cryptographic Library');
            } else {
                console.error('Could not activate Javascript Cryptographic Library');

                process.exit(1);
            }
        } else if (process.env.FORCE_WASM) {
            if (await Crypto.force_wasm_library()) {
                console.warn('Performing tests with WASM Cryptographic Library');
            } else {
                console.error('Could not activate WASM Cryptographic Library');

                process.exit(1);
            }
        } else {
            console.warn('Performing tests with Node.js C++ Addon Library');
        }

        wallet_seed = await crypto.random_hash();
    });

    describe('Hashing', async () => {
        const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

        it('Argon2d', async () => {
            const result = await crypto.argon2d(INPUT_DATA, 4, 1024, 1);

            assert(result === 'cd65323e3e56272fd19b745b0673318b21c2be5257f918267998b341719c3d5a');
        });

        it('Argon2i', async () => {
            const result = await crypto.argon2i(INPUT_DATA, 4, 1024, 1);

            assert(result === 'debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a');
        });

        it('Argon2id', async () => {
            const result = await crypto.argon2id(INPUT_DATA, 4, 1024, 1);

            assert(result === 'a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9');
        });

        it('SHA3', async () => {
            const result = await crypto.sha3(INPUT_DATA);

            assert(result === '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb');
        });

        it('SHA3 Slow Hash [0]', async () => {
            const result = await crypto.sha3_slow_hash(INPUT_DATA);

            assert(result === '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb');
        });

        it('SHA3 Slow Hash [4096]', async () => {
            const result = await crypto.sha3_slow_hash(INPUT_DATA, 4096);

            assert(result === 'c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c');
        });
    });

    describe('Base58', async () => {
        const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

        it('Encode', async () => {
            const encoded = await crypto.base58_encode(INPUT_DATA);

            const decoded = await crypto.base58_decode(encoded);

            assert(decoded === INPUT_DATA);
        });

        it('Encode Fails', async () => {
            const encoded = await crypto.base58_encode(INPUT_DATA);

            try {
                await crypto.base58_decode_check(encoded);

                assert(false);
            } catch {}
        });

        it('Encode Check', async () => {
            const encoded = await crypto.base58_encode_check(INPUT_DATA);

            const decoded = await crypto.base58_decode_check(encoded);

            assert(decoded === INPUT_DATA);
        });

        it('Encode Check Fails', async () => {
            const encoded = await crypto.base58_encode_check(INPUT_DATA);

            try {
                await crypto.base58_decode(encoded);

                assert(false);
            } catch {}
        });
    });

    describe('CryptoNote Base58', async () => {
        const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

        it('Encode', async () => {
            const encoded = await crypto.cn_base58_encode(INPUT_DATA);

            const decoded = await crypto.cn_base58_decode(encoded);

            assert(decoded === INPUT_DATA);
        });

        it('Encode Fails', async () => {
            const encoded = await crypto.cn_base58_encode(INPUT_DATA);

            try {
                await crypto.cn_base58_decode_check(encoded);

                assert(false);
            } catch {}
        });

        it('Encode Check', async () => {
            const encoded = await crypto.cn_base58_encode_check(INPUT_DATA);

            const decoded = await crypto.cn_base58_decode_check(encoded);

            assert(decoded === INPUT_DATA);
        });

        it('Encode Check Fails', async () => {
            const encoded = await crypto.cn_base58_encode_check(INPUT_DATA);

            try {
                await crypto.cn_base58_decode(encoded);

                assert(false);
            } catch {}
        });
    });

    describe('Mnemonics', async () => {
        const m_wallet_seed = 'f41f4de17ba1dd99a520f59e542a49a19cbc4f76e072cdf12205677685befd2a';
        const m_mnemonic_phrase = [
            'write', 'cream', 'phone',
            'control', 'planet', 'version',
            'believe', 'truck', 'decade',
            'enhance', 'hundred', 'save',
            'near', 'sponsor', 'assault',
            'foster', 'mushroom', 'apple',
            'picture', 'doctor', 'kiwi',
            'spawn', 'shy', 'table',
            'brother', 'speak', 'absurd',
            'abandon', 'abandon', 'abandon',
            'measure'
        ].join(' ');
        const m_mnemonic_phrase_nots = [
            'write', 'cream', 'phone',
            'control', 'planet', 'version',
            'believe', 'truck', 'decade',
            'enhance', 'hundred', 'save',
            'near', 'sponsor', 'assault',
            'foster', 'mushroom', 'apple',
            'picture', 'doctor', 'kiwi',
            'spawn', 'shy', 'table',
            'best'
        ].join(' ');
        const m_timestamp = BigInteger(1621948647);
        const m_checksum_index = 1103;

        it('Encode', async () => {
            const phrase = await crypto.mnemonics_encode(m_wallet_seed, m_timestamp);

            assert(phrase.join(' ') === m_mnemonic_phrase);
        });

        it('Encode - No Timestamp', async () => {
            const phrase = await crypto.mnemonics_encode(m_wallet_seed, 0, false);

            assert(phrase.join(' ') === m_mnemonic_phrase_nots);
        });

        it('Decode', async () => {
            const [seed, timestamp] = await crypto.mnemonics_decode(m_mnemonic_phrase.split(' '));

            assert(seed === m_wallet_seed);
            assert(timestamp.toString() === m_timestamp.toString());
        });

        it('Decode - No Timestamp', async () => {
            const [seed, timestamp] = await crypto.mnemonics_decode(m_mnemonic_phrase_nots.split(' '));

            assert(seed === m_wallet_seed);
            assert(timestamp.toJSNumber() === 0);
        });

        it('Calculate Checksum Index', async () => {
            const partial_seed = m_mnemonic_phrase.split(' ').reverse();

            partial_seed.shift();

            const index = await crypto.mnemonics_calculate_checksum_index(partial_seed.reverse());

            assert(index === m_checksum_index);
        });

        it('Word Index', async () => {
            const index = await crypto.mnemonics_word_index('measure');

            assert(index === m_checksum_index);
        });
    });

    describe('Fundamentals', async () => {
        let m_seed: any;
        let m_timestamp: any;
        let m_words: any;

        it('Calculate Base2 Exponent', async () => {
            for (let i = 0; i < 16; ++i) {
                assert(await crypto.calculate_base2_exponent(1 << i) === i);
            }
        });

        it('Check Scalar', async () => {
            assert(await crypto.check_scalar('bf356a444a9db6e5c396a36eb7207e2647c5f89db88b1e2218844bb54661910d'));
            assert(!await crypto.check_point('bf356a444a9db6e5c396a36eb7207e2647c5f89db88b1e2218844bb54661910d'));
        });

        it('Check Point', async () => {
            assert(!await crypto.check_scalar('9f18b169834781952bdb781384147db67b1674a32103950c23491ad2ca850258'));
            assert(await crypto.check_point('9f18b169834781952bdb781384147db67b1674a32103950c23491ad2ca850258'));
        });

        it('Random Scalar', async () => {
            const scalar = await crypto.random_scalar();

            assert(await crypto.check_scalar(scalar));
        });

        it('Random Point', async () => {
            const point = await crypto.random_point();

            assert(await crypto.check_point(point));
        });

        it('Random Hash', async () => {
            assert(typeof await crypto.random_hash() !== 'undefined');
        });

        it('Generate Random Keys', async () => {
            const [public_key, secret_key] = await crypto.generate_keys();

            assert(await crypto.check_point(public_key));
            assert(await crypto.check_scalar(secret_key));
        });

        it('Secret Key to Public Key', async () => {
            const [public_key, secret_key] = await crypto.generate_keys();

            const public_key2 = await crypto.secret_key_to_public_key(secret_key);

            assert(public_key === public_key2);
        });

        it('Generate Wallet Seed', async () => {
            const [seed, words, timestamp] = await crypto.generate_wallet_seed();

            assert(timestamp.toJSNumber() !== 0);
            assert(seed.length === 64);
            assert(words.length !== 0);

            m_seed = seed;
            m_words = words;
            m_timestamp = timestamp;
        });

        it('Restore Wallet Seed', async () => {
            const [seed, timestamp] = await crypto.restore_wallet_seed(m_words);

            assert(seed === m_seed);
            assert(timestamp.toJSNumber() === m_timestamp.toJSNumber());
        });

        it('Generate Spend Keys From Wallet Seed', async () => {
            const [, secret_spend_key] = await crypto.generate_wallet_spend_keys(wallet_seed);

            assert(secret_spend_key !== wallet_seed);
        });

        it('Generate View Keys From Wallet Seed', async () => {
            const [public_spend_key, secret_spend_key] = await crypto.generate_wallet_spend_keys(wallet_seed);

            const [public_view_key, secret_view_key] = await crypto.generate_wallet_view_keys(wallet_seed);

            assert(public_spend_key !== public_view_key);
            assert(secret_spend_key !== secret_view_key);
        });
    });

    describe('Stealth Addresses', async () => {
        const public_key = 'f572a598c02f19b81e205f31cbb23bbc4997a8e8cd5aacd1c6f11b50b0760a2d';
        const secret_key = '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909';
        const derivation = '765e9a3ad29efabb9d749e87ac817ce4d1e105600b7e5fd0e335ee87bc1f08aa';
        const public_ephemeral = '8692c8d93cc07d2ce9126fed65214a86129383b464598bfa57b1368b91d875f6';
        const secret_ephemeral = '20ceeb1074cc86b9029406f48079d71d06060d8a5a1cfb7e3f2fef897a6a9303';
        const key_image = '62384706087b9dc3d77e510725478678c4c2350feff5117eb3e55436b7c2c128';
        const key_image_2 = '83451e45ea1531430a94a94dfe69515ec1111d69ec9cee8d5751bfc84450314a';
        let dervscalar: string;

        before(async () => {
            dervscalar = await crypto.derivation_to_scalar(derivation, 2);
        });

        it('Generate Key Derivation', async () => {
            const derv = await crypto.generate_key_derivation(public_key, secret_key);

            assert(derv === derivation);
        });

        it('Derive Public Key', async () => {
            const key = await crypto.derive_public_key(dervscalar, public_key);

            assert(key === public_ephemeral);
        });

        it('Derive Secret Key', async () => {
            const key = await crypto.derive_secret_key(dervscalar, secret_key);

            assert(key === secret_ephemeral);
        });

        it('Underive Public Key', async () => {
            const key = await crypto.underive_public_key(
                derivation, 2, public_ephemeral);

            assert(key === public_key);
        });

        it('Generate Key Image', async () => {
            const key = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);

            assert(key === key_image);
        });

        it('Generate Key Image v2', async () => {
            const key = await crypto.generate_key_image_v2(secret_ephemeral);

            assert(key === key_image_2);
        });
    });

    describe('Deterministic Subwallets', async () => {
        const wallet_seed = '7c6e07d6ec21f16431331dce52c3ff90aeb97d5e46dc18422e6fe2d456add603';

        it('Generate Subwallet #0', async () => {
            const [, sec] = await crypto.generate_wallet_spend_keys(wallet_seed, 0);

            assert(sec !== wallet_seed);
        });

        it('Generate Subwallet #999', async () => {
            const [, sec] = await crypto.generate_wallet_spend_keys(wallet_seed, 999);

            assert(sec !== wallet_seed);
        });

        it('Generate Subwallet #512000', async () => {
            const [, sec] = await crypto.generate_wallet_spend_keys(wallet_seed, 512000);

            assert(sec !== wallet_seed);
        });
    });

    describe('Ring Signatures', async () => {
        let message_digest: string, public_ephemeral: string,
            secret_ephemeral: string, key_image: string, public_keys: string[],
            key_image2: string;

        // commitment info
        let input_blinding: string, input_commitment: string, public_commitments: string[],
            pseudo_blinding: string, pseudo_commitment: string;

        const RING_SIZE = 8;
        const REAL_OUTPUT_INDEX = 3;

        before(async () => {
            message_digest = await crypto.random_scalar();

            [public_ephemeral, secret_ephemeral] = await crypto.generate_keys();

            key_image = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);

            key_image2 = await crypto.generate_key_image_v2(secret_ephemeral);

            public_keys = await crypto.random_points(RING_SIZE);

            public_keys[REAL_OUTPUT_INDEX] = public_ephemeral;

            input_blinding = await crypto.random_scalar();

            input_commitment = await crypto.generate_pedersen_commitment(input_blinding, 100);

            public_commitments = await crypto.random_points(RING_SIZE);

            public_commitments[REAL_OUTPUT_INDEX] = input_commitment;

            const [blindings, commitments] =
                await crypto.generate_pseudo_commitments([100],
                    await crypto.random_scalars(1));

            pseudo_blinding = blindings[0];

            pseudo_commitment = commitments[0];
        });

        describe('Borromean', async () => {
            it('Generate Ring Signature', async () => {
                const signature = await crypto.borromean_generate_ring_signature(
                    message_digest,
                    secret_ephemeral,
                    public_keys);

                const pass = await crypto.borromean_check_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    signature);

                assert(pass === true);
            });

            it('Prepare Ring Signature', async () => {
                const prepared = await crypto.borromean_prepare_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    REAL_OUTPUT_INDEX);

                const signature = await crypto.borromean_complete_ring_signature(
                    secret_ephemeral,
                    REAL_OUTPUT_INDEX,
                    prepared);

                const pass = await crypto.borromean_check_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    signature);

                assert(pass === true);
            });
        });

        describe('CLSAG', async () => {
            it('Generate Ring Signature', async () => {
                const signature = await crypto.clsag_generate_ring_signature(
                    message_digest,
                    secret_ephemeral,
                    public_keys);

                const pass = await crypto.clsag_check_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    signature);

                assert(pass === true);
            });

            it('Prepare Ring Signature', async () => {
                const [prepared, h, mu_P] = await crypto.clsag_prepare_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    REAL_OUTPUT_INDEX);

                const signature = await crypto.clsag_complete_ring_signature(
                    secret_ephemeral,
                    REAL_OUTPUT_INDEX,
                    prepared,
                    h,
                    mu_P);

                const pass = await crypto.clsag_check_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    signature);

                assert(pass === true);
            });
        });

        describe('CLSAG with Commitments', async () => {
            it('Generate Ring Signature', async () => {
                const signature = await crypto.clsag_generate_ring_signature(
                    message_digest,
                    secret_ephemeral,
                    public_keys,
                    input_blinding,
                    public_commitments,
                    pseudo_blinding,
                    pseudo_commitment);

                const pass = await crypto.clsag_check_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    signature,
                    public_commitments);

                assert(pass === true);
            });

            it('Prepare Ring Signature', async () => {
                const [prepared, h, mu_P] = await crypto.clsag_prepare_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    REAL_OUTPUT_INDEX,
                    input_blinding,
                    public_commitments,
                    pseudo_blinding,
                    pseudo_commitment);

                const signature = await crypto.clsag_complete_ring_signature(
                    secret_ephemeral,
                    3,
                    prepared,
                    h,
                    mu_P);

                const pass = await crypto.clsag_check_ring_signature(
                    message_digest,
                    key_image,
                    public_keys,
                    signature,
                    public_commitments);

                assert(pass === true);
            });
        });

        describe('Triptych', async () => {
            it('Generate Ring Signature', async () => {
                const signature = await crypto.triptych_generate_ring_signature(
                    message_digest,
                    secret_ephemeral,
                    public_keys,
                    input_blinding,
                    public_commitments,
                    pseudo_blinding,
                    pseudo_commitment);

                const pass = await crypto.triptych_check_ring_signature(
                    message_digest,
                    key_image2,
                    public_keys,
                    signature,
                    public_commitments);

                assert(pass === true);
            });

            it('Prepare Ring Signature', async () => {
                const [prepared, xpow] = await crypto.triptych_prepare_ring_signature(
                    message_digest,
                    key_image2,
                    public_keys,
                    REAL_OUTPUT_INDEX,
                    input_blinding,
                    public_commitments,
                    pseudo_blinding,
                    pseudo_commitment);

                const signature = await crypto.triptych_complete_ring_signature(
                    secret_ephemeral,
                    prepared,
                    xpow);

                const pass = await crypto.triptych_check_ring_signature(
                    message_digest,
                    key_image2,
                    public_keys,
                    signature,
                    public_commitments);

                assert(pass === true);
            });
        });
    });

    describe('RingCT', async () => {
        let blinding_factors: string[], C_1: string, C_2: string, C_fee: string, pseudo_commitments: string[];

        before(async () => {
            blinding_factors = await crypto.random_scalars(2);
        });

        it('Generate Pedersen Commitment', async () => {
            C_1 = await crypto.generate_pedersen_commitment(blinding_factors[0], 1500);

            C_2 = await crypto.generate_pedersen_commitment(blinding_factors[1], 2000);

            assert(C_1 !== C_2);
        });

        it('Generate Transaction Fee Commitment', async () => {
            C_fee = await crypto.generate_transaction_fee_commitment(100);

            assert(C_fee !== C_1 && C_fee !== C_2);
        });

        it('Generate Pseudo Commitments', async () => {
            [, pseudo_commitments] = await crypto.generate_pseudo_commitments(
                [3000, 600], blinding_factors);

            assert(pseudo_commitments.length === 2);
        });

        it('Check Commitments Parity', async () => {
            assert(await crypto.check_commitments_parity(pseudo_commitments, [C_1, C_2], 100));
        });

        it('Fail Check Commitments Parity', async () => {
            assert(!await crypto.check_commitments_parity(pseudo_commitments, [C_1, C_2], 300));
        });

        it('Amount Masking', async () => {
            const amount = 13371337;

            const amount_mask = await crypto.generate_amount_mask(blinding_factors[0]);

            const masked_amount = await crypto.toggle_masked_amount(amount_mask, amount);

            const unmasked_amount = await crypto.toggle_masked_amount(amount_mask, masked_amount);

            const amount_mask2 = await crypto.generate_amount_mask(blinding_factors[1]);

            const unmasked_amount2 = await crypto.toggle_masked_amount(amount_mask2, masked_amount);

            assert(masked_amount !== unmasked_amount);
            assert(unmasked_amount.toJSNumber() === amount);
            assert(unmasked_amount2 !== unmasked_amount);
        });
    });

    describe('Range Proofs', async () => {
        describe('Bulletproofs', async () => {
            let proof: crypto_bulletproof_t, commitments: string[];

            it('Prove', async () => {
                [proof, commitments] = await crypto.bulletproofs_prove(
                    [10000], await crypto.random_scalars(1));

                assert(await crypto.bulletproofs_verify([proof], [commitments]));
            });

            it('Batched Verification', async () => {
                const valid = await crypto.bulletproofs_verify(
                    [proof, proof], [commitments, commitments]);

                assert(valid);
            });

            it('Big Batch Verification', async () => {
                const valid = await crypto.bulletproofs_verify(
                    [proof, proof, proof, proof, proof, proof],
                    [commitments, commitments, commitments, commitments, commitments, commitments]);

                assert(valid);
            });

            it('Fail Verification', async () => {
                const fake_commitments = await crypto.random_points(1);

                assert(!await crypto.bulletproofs_verify([proof], [fake_commitments]));
            });
        });

        describe('Bulletproofs+', async () => {
            let proof: crypto_bulletproof_plus_t, commitments: string[];

            it('Prove', async () => {
                [proof, commitments] = await crypto.bulletproofsplus_prove(
                    [10000], await crypto.random_scalars(1));

                const pass = await crypto.bulletproofsplus_verify([proof], [commitments]);

                assert(pass === true);
            });

            it('Batched Verification', async () => {
                const pass = await crypto.bulletproofsplus_verify(
                    [proof, proof], [commitments, commitments]);

                assert(pass === true);
            });

            it('Big Batch Verification', async () => {
                const pass = await crypto.bulletproofsplus_verify(
                    [proof, proof, proof, proof, proof, proof],
                    [commitments, commitments, commitments, commitments, commitments, commitments]);

                assert(pass === true);
            });

            it('Fail Verification', async () => {
                const fake_commitments = await crypto.random_points(1);

                const pass = await crypto.bulletproofsplus_verify([proof], [fake_commitments]);

                assert(pass === false);
            });
        });
    });

    describe('Multisig', async () => {
        let party1: Participant, party2: Participant, party3: Participant;
        const output_index = 3;

        // commitment info
        let input_blinding: string, input_commitment: string, public_commitments: string[],
            pseudo_blinding: string, pseudo_commitment: string;

        const generate_party = async (): Promise<Participant> => {
            const wallet_seed = await crypto.random_hash();

            const [public_spend_key, secret_spend_key] = await crypto.generate_wallet_spend_keys(wallet_seed);

            const [public_view_key, secret_view_key] = await crypto.generate_wallet_view_keys(wallet_seed);

            return {
                spend: { public: public_spend_key, secret: secret_spend_key },
                view: { public: public_view_key, secret: secret_view_key },
                multisig: { publics: [], secrets: [] }
            };
        };

        const generate_sig = async (public_ephemeral: string, ...parties: Participant[]): Promise<boolean> => {
            const message_digest = await crypto.random_scalar();

            const prepared = await crypto.prepare_signature(message_digest, public_ephemeral);

            const keys: string[] = [];

            for (const party of parties) {
                const key = await crypto.generate_partial_signing_scalar(prepared, party.spend.secret);

                keys.push(key);
            }

            const signature = await crypto.complete_signature(undefined, prepared, keys);

            return crypto.check_signature(message_digest, public_ephemeral, signature);
        };

        const generate_borromean = async (
            derivation_scalar: string, public_ephemeral: string,
            key_image: string, ...parties: Participant[]): Promise<boolean> => {
            const message_digest = await crypto.random_scalar();

            const public_keys = await crypto.random_points(4);

            public_keys[output_index] = public_ephemeral;

            const prepared = await crypto.borromean_prepare_ring_signature(
                message_digest, key_image, public_keys, output_index);

            const keys: string[] = [];

            for (const party of parties) {
                const key = await crypto.borromean_generate_partial_signing_scalar(
                    output_index, prepared, party.spend.secret);

                keys.push(key);
            }

            const signature = await crypto.borromean_complete_ring_signature(
                derivation_scalar, output_index, prepared, keys);

            return crypto.borromean_check_ring_signature(
                message_digest, key_image, public_keys, signature);
        };

        const generate_clsag = async (derivation_scalar: string, public_ephemeral: string, key_image: string,
            ...parties: Participant[]): Promise<boolean> => {
            const message_digest = await crypto.random_scalar();

            const public_keys = await crypto.random_points(4);

            public_keys[output_index] = public_ephemeral;

            const [prepared, h, mu_P] = await crypto.clsag_prepare_ring_signature(
                message_digest,
                key_image,
                public_keys,
                output_index);

            const keys: string[] = [];

            for (const party of parties) {
                const key = await crypto.clsag_generate_partial_signing_scalar(mu_P, party.spend.secret);

                keys.push(key);
            }

            const signature = await crypto.clsag_complete_ring_signature(
                derivation_scalar,
                output_index,
                prepared,
                h,
                mu_P,
                keys);

            return crypto.clsag_check_ring_signature(
                message_digest,
                key_image,
                public_keys,
                signature);
        };

        const generate_clsag_com = async (derivation_scalar: string, public_ephemeral: string, key_image: string,
            ...parties: Participant[]): Promise<boolean> => {
            const message_digest = await crypto.random_scalar();

            const public_keys = await crypto.random_points(4);

            public_keys[output_index] = public_ephemeral;

            const [prepared, h, mu_P] = await crypto.clsag_prepare_ring_signature(
                message_digest,
                key_image,
                public_keys,
                output_index,
                input_blinding,
                public_commitments,
                pseudo_blinding,
                pseudo_commitment);

            const keys: string[] = [];

            for (const party of parties) {
                const key = await crypto.clsag_generate_partial_signing_scalar(mu_P, party.spend.secret);

                keys.push(key);
            }

            const signature = await crypto.clsag_complete_ring_signature(
                derivation_scalar,
                output_index,
                prepared,
                h,
                mu_P,
                keys);

            return crypto.clsag_check_ring_signature(
                message_digest,
                key_image,
                public_keys,
                signature,
                public_commitments);
        };

        const generate_key_image = async (derivation_scalar: string, public_ephemeral: string,
            key_image: string, ...parties: Participant[]): Promise<boolean> => {
            const keys: string[] = [];

            for (const party of parties) {
                const key = await crypto.generate_key_image(public_ephemeral, party.spend.secret);

                keys.push(key);
            }

            const restored_image = await crypto.generate_key_image(public_ephemeral, derivation_scalar,
                keys);

            return restored_image === key_image;
        };

        before(async () => {
            party1 = await generate_party();

            party2 = await generate_party();

            party3 = await generate_party();

            input_blinding = await crypto.random_scalar();

            input_commitment = await crypto.generate_pedersen_commitment(input_blinding, 100);

            public_commitments = await crypto.random_points(4);

            public_commitments[output_index] = input_commitment;

            const [blindings, commitments] =
                await crypto.generate_pseudo_commitments([100],
                    await crypto.random_scalars(1));

            pseudo_blinding = blindings[0];

            pseudo_commitment = commitments[0];
        });

        describe('N/N', async () => {
            let public_ephemeral: string, secret_ephemeral: string,
                derivation: string, derivation_scalar: string,
                tx_public_key: string, tx_private_key: string, key_image: string, shared_spend_public_key: string;

            before(async () => {
                [tx_public_key, tx_private_key] = await crypto.generate_keys();

                const shared_view_secret_key = await crypto.generate_shared_secret_key(
                    [party1.view.secret, party2.view.secret, party3.view.secret]);

                const shared_spend_secret_key = await crypto.generate_shared_secret_key(
                    [party1.spend.secret, party2.spend.secret, party3.spend.secret]);

                const shared_view_public_key = await crypto.generate_shared_public_key(
                    [party1.view.public, party2.view.public, party3.view.public]);

                shared_spend_public_key = await crypto.generate_shared_public_key(
                    [party1.spend.public, party2.spend.public, party3.spend.public]);

                const check_view_key = await crypto.secret_key_to_public_key(shared_view_secret_key);

                const check_spend_key = await crypto.secret_key_to_public_key(shared_spend_secret_key);

                assert(check_view_key === shared_view_public_key && check_spend_key === shared_spend_public_key);

                derivation = await crypto.generate_key_derivation(shared_view_public_key, tx_private_key);

                const check_derivation = await crypto.generate_key_derivation(tx_public_key, shared_view_secret_key);

                assert(check_derivation === derivation);

                derivation_scalar = await crypto.derivation_to_scalar(derivation, output_index);

                public_ephemeral = await crypto.derive_public_key(derivation_scalar, shared_spend_public_key);

                secret_ephemeral = await crypto.derive_secret_key(derivation_scalar, shared_spend_secret_key);

                key_image = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);
            });

            describe('Signature from Partial Signing Keys', async () => {
                it('Fail #1', async () => {
                    assert(!await generate_sig(shared_spend_public_key, party1));
                });

                it('Fail #2', async () => {
                    assert(!await generate_sig(shared_spend_public_key, party2));
                });

                it('Fail #3', async () => {
                    assert(!await generate_sig(shared_spend_public_key, party3));
                });

                it('Fail #1 & #2', async () => {
                    assert(!await generate_sig(shared_spend_public_key, party1, party2));
                });

                it('Fail #1 & #3', async () => {
                    assert(!await generate_sig(shared_spend_public_key, party1, party3));
                });

                it('Fail #2 & #3', async () => {
                    assert(!await generate_sig(shared_spend_public_key, party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await generate_sig(shared_spend_public_key, party1, party2, party3));
                });
            });

            describe('Generate Key Image from Partial Key Images', async () => {
                it('Fail #1', async () => {
                    assert(!await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party1));
                });

                it('Fail #2', async () => {
                    assert(!await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party2));
                });

                it('Fail #3', async () => {
                    assert(!await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party3));
                });

                it('Fail #1 & #2', async () => {
                    assert(!await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party1, party2));
                });

                it('Fail #1 & #3', async () => {
                    assert(!await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party1, party3));
                });

                it('Fail #2 & #3', async () => {
                    assert(!await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await generate_key_image(
                        derivation_scalar, public_ephemeral, key_image, party1, party2, party3));
                });
            });

            describe('Generate v2 Key Image from Partial Key Images', async () => {
                it('Fail #1', async function () {
                    return this.skip();
                });

                it('Fail #2', async function () {
                    return this.skip();
                });

                it('Fail #3', async function () {
                    return this.skip();
                });

                it('Fail #1 & #2', async function () {
                    return this.skip();
                });

                it('Fail #1 & #3', async function () {
                    return this.skip();
                });

                it('Fail #2 & #3', async function () {
                    return this.skip();
                });

                it('Succeed #1 & #2 & #3', async function () {
                    return this.skip();
                });
            });

            describe('Borromean Ring Signature from Partial Signing Keys', async () => {
                it('Fail #1', async () => {
                    assert(!await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party1));
                });

                it('Fail #2', async () => {
                    assert(!await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party2));
                });

                it('Fail #3', async () => {
                    assert(!await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party3));
                });

                it('Fail #1 & #2', async () => {
                    assert(!await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party1, party2));
                });

                it('Fail #1 & #3', async () => {
                    assert(!await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party1, party3));
                });

                it('Fail #2 & #3', async () => {
                    assert(!await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await generate_borromean(derivation_scalar, public_ephemeral, key_image,
                        party1, party2, party3));
                });
            });

            describe('CLSAG Ring Signature from Partial Signing Keys', async () => {
                it('Fail #1', async () => {
                    assert(!await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party1));
                });

                it('Fail #2', async () => {
                    assert(!await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party2));
                });

                it('Fail #3', async () => {
                    assert(!await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party3));
                });

                it('Fail #1 & #2', async () => {
                    assert(!await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party1, party2));
                });

                it('Fail #1 & #3', async () => {
                    assert(!await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party1, party3));
                });

                it('Fail #2 & #3', async () => {
                    assert(!await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party1, party2));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await generate_clsag(derivation_scalar, public_ephemeral, key_image,
                        party1, party2, party3));
                });
            });

            describe('CLSAG Ring Signature w/ Commitments from Partial Signing Keys', async () => {
                it('Fail #1', async () => {
                    assert(!await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party1));
                });

                it('Fail #2', async () => {
                    assert(!await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party2));
                });

                it('Fail #3', async () => {
                    assert(!await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party3));
                });

                it('Fail #1 & #2', async () => {
                    assert(!await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party1, party2));
                });

                it('Fail #1 & #3', async () => {
                    assert(!await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party1, party3));
                });

                it('Fail #2 & #3', async () => {
                    assert(!await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party1, party2));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await generate_clsag_com(derivation_scalar, public_ephemeral, key_image,
                        party1, party2, party3));
                });
            });

            describe('Triptych Ring Signature from Partial Signing Keys', async () => {
                it('Fail #1', async function () {
                    return this.skip();
                });

                it('Fail #2', async function () {
                    return this.skip();
                });

                it('Fail #3', async function () {
                    return this.skip();
                });

                it('Fail #1 & #2', async function () {
                    return this.skip();
                });

                it('Fail #1 & #3', async function () {
                    return this.skip();
                });

                it('Fail #2 & #3', async function () {
                    return this.skip();
                });

                it('Succeed #1 & #2 & #3', async function () {
                    return this.skip();
                });
            });
        });

        describe('N-1/N', async () => {
            let public_ephemeral: string, secret_ephemeral: string,
                derivation: string, derivation_scalar: string,
                tx_public_key: string, tx_private_key: string, key_image: string, shared_spend_public_key: string;

            before(async () => {
                [tx_public_key, tx_private_key] = await crypto.generate_keys();

                party1.multisig.secrets = await crypto.generate_multisig_secret_keys(
                    [party2.spend.public, party3.spend.public], party1.spend.secret);

                party2.multisig.secrets = await crypto.generate_multisig_secret_keys(
                    [party1.spend.public, party3.spend.public], party2.spend.secret);

                party3.multisig.secrets = await crypto.generate_multisig_secret_keys(
                    [party1.spend.public, party2.spend.public], party3.spend.secret);

                for (const key of party1.multisig.secrets) {
                    party1.multisig.publics.push(await crypto.secret_key_to_public_key(key));
                }

                for (const key of party2.multisig.secrets) {
                    party2.multisig.publics.push(await crypto.secret_key_to_public_key(key));
                }

                for (const key of party3.multisig.secrets) {
                    party3.multisig.publics.push(await crypto.secret_key_to_public_key(key));
                }

                const shared_view_secret_key = await crypto.generate_shared_secret_key(
                    [party1.view.secret, party2.view.secret, party3.view.secret]);

                const shared_spend_secret_key = await crypto.generate_shared_secret_key(
                    [...party1.multisig.secrets, ...party2.multisig.secrets, ...party3.multisig.secrets]);

                const shared_view_public_key = await crypto.generate_shared_public_key(
                    [party1.view.public, party2.view.public, party3.view.public]);

                shared_spend_public_key = await crypto.generate_shared_public_key(
                    [...party1.multisig.publics, ...party2.multisig.publics, ...party3.multisig.publics]);

                const check_view_key = await crypto.secret_key_to_public_key(shared_view_secret_key);

                const check_spend_key = await crypto.secret_key_to_public_key(shared_spend_secret_key);

                assert(check_view_key === shared_view_public_key && check_spend_key === shared_spend_public_key);

                derivation = await crypto.generate_key_derivation(shared_view_public_key, tx_private_key);

                const check_derivation = await crypto.generate_key_derivation(tx_public_key, shared_view_secret_key);

                assert(check_derivation === derivation);

                derivation_scalar = await crypto.derivation_to_scalar(derivation, output_index);

                public_ephemeral = await crypto.derive_public_key(derivation_scalar, shared_spend_public_key);

                secret_ephemeral = await crypto.derive_secret_key(derivation_scalar, shared_spend_secret_key);

                key_image = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);
            });

            describe('Signature from Partial Signing Keys', async () => {
                const execute_sig = async (...parties: Participant[]): Promise<boolean> => {
                    const message_digest = ''.padStart(64, '1');

                    const prepared = await crypto.prepare_signature(
                        message_digest, shared_spend_public_key);

                    const partial_signing_scalars: string[] = [];

                    for (const party of parties) {
                        for (const key of party.multisig.secrets) {
                            partial_signing_scalars.push(await crypto.generate_partial_signing_scalar(
                                prepared, key));
                        }
                    }

                    const signature = await crypto.complete_signature(
                        undefined, prepared, partial_signing_scalars);

                    return crypto.check_signature(
                        message_digest, shared_spend_public_key, signature);
                };

                it('Fail #1', async () => {
                    assert(!await execute_sig(party1));
                });

                it('Fail #2', async () => {
                    assert(!await execute_sig(party2));
                });

                it('Fail #3', async () => {
                    assert(!await execute_sig(party3));
                });

                it('Succeed #1 & #2', async () => {
                    assert(await execute_sig(party1, party2));
                });

                it('Succeed #1 & #3', async () => {
                    assert(await execute_sig(party1, party3));
                });

                it('Succeed #2 & #3', async () => {
                    assert(await execute_sig(party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await execute_sig(party1, party2, party3));
                });
            });

            const execute_key_image = async (...parties: Participant[]): Promise<boolean> => {
                const partial_key_images: string[] = [];

                for (const party of parties) {
                    for (const key of party.multisig.secrets) {
                        partial_key_images.push(await crypto.generate_key_image(public_ephemeral, key));
                    }
                }

                const restored_image = await crypto.generate_key_image(public_ephemeral, derivation_scalar,
                    partial_key_images);

                return restored_image === key_image;
            };

            describe('Generate Key Image from Partial Key Images', async () => {
                it('Fail #1', async () => {
                    assert(!await execute_key_image(party1));
                });

                it('Fail #2', async () => {
                    assert(!await execute_key_image(party2));
                });

                it('Fail #3', async () => {
                    assert(!await execute_key_image(party3));
                });

                it('Succeed #1 & #2', async () => {
                    assert(await execute_key_image(party1, party2));
                });

                it('Succeed #1 & #3', async () => {
                    assert(await execute_key_image(party1, party3));
                });

                it('Succeed #2 & #3', async () => {
                    assert(await execute_key_image(party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await execute_key_image(party1, party2, party3));
                });
            });

            describe('Borromean Ring Signature from Partial Signing Keys', async () => {
                const execute_borromean = async (...parties: Participant[]): Promise<boolean> => {
                    const message_digest = await crypto.random_scalar();

                    const public_keys = await crypto.random_points(4);

                    public_keys[output_index] = public_ephemeral;

                    const prepared = await crypto.borromean_prepare_ring_signature(
                        message_digest, key_image, public_keys, output_index);

                    const partial_signing_scalars: string[] = [];

                    for (const party of parties) {
                        for (const key of party.multisig.secrets) {
                            partial_signing_scalars.push(await crypto.borromean_generate_partial_signing_scalar(
                                output_index, prepared, key));
                        }
                    }

                    const signature = await crypto.borromean_complete_ring_signature(
                        derivation_scalar, output_index, prepared, partial_signing_scalars);

                    return crypto.borromean_check_ring_signature(
                        message_digest, key_image, public_keys, signature);
                };

                it('Fail #1', async () => {
                    assert(!await execute_borromean(party1));
                });

                it('Fail #2', async () => {
                    assert(!await execute_borromean(party2));
                });

                it('Fail #3', async () => {
                    assert(!await execute_borromean(party3));
                });

                it('Succeed #1 & #2', async () => {
                    assert(await execute_borromean(party1, party2));
                });

                it('Succeed #1 & #3', async () => {
                    assert(await execute_borromean(party1, party3));
                });

                it('Succeed #2 & #3', async () => {
                    assert(await execute_borromean(party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await execute_borromean(party1, party2, party3));
                });
            });

            describe('CLSAG Ring Signature from Partial Signing Keys', async () => {
                const execute_clsag = async (...parties: Participant[]): Promise<boolean> => {
                    const message_digest = await crypto.random_scalar();

                    const public_keys = await crypto.random_points(4);

                    public_keys[output_index] = public_ephemeral;

                    const [prepared, h, mu_P] = await crypto.clsag_prepare_ring_signature(
                        message_digest, key_image, public_keys, output_index);

                    const partial_signing_scalars: string[] = [];

                    for (const party of parties) {
                        for (const key of party.multisig.secrets) {
                            partial_signing_scalars.push(await crypto.clsag_generate_partial_signing_scalar(mu_P, key));
                        }
                    }

                    const signature = await crypto.clsag_complete_ring_signature(derivation_scalar, output_index,
                        prepared, h, mu_P, partial_signing_scalars);

                    return crypto.clsag_check_ring_signature(
                        message_digest, key_image, public_keys, signature);
                };

                it('Fail #1', async () => {
                    assert(!await execute_clsag(party1));
                });

                it('Fail #2', async () => {
                    assert(!await execute_clsag(party2));
                });

                it('Fail #3', async () => {
                    assert(!await execute_clsag(party3));
                });

                it('Succeed #1 & #2', async () => {
                    assert(await execute_clsag(party1, party2));
                });

                it('Succeed #1 & #3', async () => {
                    assert(await execute_clsag(party1, party3));
                });

                it('Succeed #2 & #3', async () => {
                    assert(await execute_clsag(party2, party3));
                });

                it('Succeed #1 & #2 & #3', async () => {
                    assert(await execute_clsag(party1, party2, party3));
                });
            });

            describe('Triptych Ring Signature from Partial Signing Keys', async () => {
                it('Fail #1', async function () {
                    return this.skip();
                });

                it('Fail #2', async function () {
                    return this.skip();
                });

                it('Fail #3', async function () {
                    return this.skip();
                });

                it('Succeed #1 & #2', async function () {
                    return this.skip();
                });

                it('Succeed #1 & #3', async function () {
                    return this.skip();
                });

                it('Succeed #2 & #3', async function () {
                    return this.skip();
                });

                it('Succeed #1 & #2 & #3', async function () {
                    return this.skip();
                });
            });
        });
    });

    describe('Check User Config', async () => {
        const sha3 = (input: string): Promise<string> => {
            try {
                return Promise.resolve(sha3_256(Buffer.from(input, 'hex')));
            } catch (e) {
                return Promise.reject(e);
            }
        };

        const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';
        const HASH = '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb';

        it('Test #1', async () => {
            crypto.userConfig.sha3 = sha3;

            const result = await crypto.sha3(INPUT_DATA);

            assert(result === HASH);
        });
    });
});
