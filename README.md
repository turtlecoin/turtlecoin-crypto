![image](https://user-images.githubusercontent.com/34389545/35821974-62e0e25c-0a70-11e8-87dd-2cfffeb6ed47.png)

# TurtleCoin: Standalone Cryptography Library

![Prerequisite](https://img.shields.io/badge/node-%3E%3D12-blue.svg) [![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/turtlecoin/turtlecoin-crypto/graphs/commit-activity) [![License: BSD-3](https://img.shields.io/badge/License-BSD--3-green.svg)](https://github.com/turtlecoin/turtlecoin-crypto/blob/master/LICENSE) [![Twitter: _TurtleCoin](https://img.shields.io/twitter/follow/_TurtleCoin.svg?style=social)](https://twitter.com/_TurtleCoin)

#### Master Build Status
[![Build Status](https://github.com/turtlecoin/turtlecoin-crypto/workflows/CI%20Build%20Tests/badge.svg?branch=master)](https://github.com/turtlecoin/turtlecoin-crypto/actions)

#### Development Build Status
[![Build Status](https://github.com/turtlecoin/turtlecoin-crypto/workflows/CI%20Build%20Tests/badge.svg?branch=development)](https://github.com/turtlecoin/turtlecoin-crypto/actions)

This repository a standalone cryptographic primitive wrapper library that can be included in various other projects in a variety of development environments, including:

* Node.js >= 12.x
* C++
* WASM
* Javascript asm.js

### Features

* Core Structure Types
  * `crypto_hash_t`: 256-bit hash
    * Aliases:
      * `crypto_seed_t`
  * `crypto_point_t`: Elliptic Curve Point
    * Caching of commonly used `ge` types
    * Aliases:
      * `crypto_public_key_t`
      * `crypto_derivation_t`
      * `crypto_key_image_t`
      * `crypto_pedersen_commitment_t`
  * `crypto_scalar_t`: Elliptic Curve Scalar
    * Aliases:
      * `crypto_secret_key_t`
      * `crypto_blinding_factor_t`
  * `crypto_signature_t`: 512-bit message signature
* [SHA3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) (256-bit)
  * Simple KDF via `sha3_slow_hash()`
* [Argon2](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf) Hashing
  * Argon2d
  * Argon2i
  * Argon2id
* [Base58 Encoding](https://tools.ietf.org/html/draft-msporny-base58-02)
  * With or Without Checksum Calculations/Checks
  * **Note:** This implementation is **not** block-based and will not work with block-based Base58 encoding (ie. CryptoNote)
* [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) Key Generation & Manipulation
  * Deterministic Subwallet Key Generation
  * Deterministic Secondary Key Generation (View Key)
* [Message Signing](https://tools.ietf.org/html/rfc8032)
  * Multisig Supported
* [Borromean](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) Ring Signatures
  * Multisig Supported
* [CLSAG](https://eprint.iacr.org/2019/654.pdf) Ring Signatures
  * Multisig Supported
* [RingCT](https://eprint.iacr.org/2015/1098.pdf)
  * [Pedersen Commitments](https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF)
  * Pseudo Commitments
  * Blinding Factors
  * Amount Masking
* [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) Range Proofs
  * Variable bit length proofs (1 to 64 bits)
  * No limits to number of values proved or verified in a single call
  * Batch Verification
  * Implements caching of common points for faster repeat calls to `prove()` and `verify()`
* [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf) Range Proofs
  * Variable bit length proofs (1 to 64 bits)
  * No limits to number of values proved or verified in a single call
  * Batch Verification
  * Implements caching of common points for faster repeat calls to `prove()` and `verify()`
* [Arcturus](https://eprint.iacr.org/2020/312.pdf) Proofs (Ring Signatures)
  * Proving & Verification
  * **Multisig in Development**
* Scalar Transcripts (C++ Only)
* Byte/Binary Serialization & De-Serialization (C++ only)
* Structure to/from JSON provided via RapidJSON (C++ only)
* Structure to/from hexadecimal encoded string representations (C++ only)
* Human Readable Code
  * Overloaded structures keep the code clean
* One Header for all `#include <crypto.h>`

### This library is NOT compatible with TurtleCoin pre-2.0.0

It is a brand new, from scratch implementation of the concepts implemented within. It contains library specific hash domains, challenge constructions, seeds, and other changes that make it practically 100% incompatible with any other library or implementation. Wallets generated with this wrapper are deterministically generated in an entirely different way and are not compatible with legacy implementations.

Do not open issues when this library does not work with TurtleCoin pre-2.0.0 or any other CryptoNote based project -- they will be closed. Legacy support and alternate implementations are not within the scope of this project.

## Javascript Library

**Note:** We build prebuilds of the Node.js native addon module as well as the WASM/JS binaries that are included for distribution with the NPM installed version of this package to speed up your development efforts.

If the prebuild for your system does not exist, it will compile the Node.js native addon module using CMake automatically.

### Dependencies

* [Node.js](https://nodejs.org) >= +12.x LTS (or Node v12)
* Compiler supporting C++17 (gcc/clang/etc)

### Node.js / Typescript / Javascript Installation

#### Yarn
```bash
yarn add @turtlecoin/crypto
```

#### NPM
```bash
npm install @turtlecoin/crypto
```

### Intialization

#### TypeScript

```javascript
import { Crypto } from '@turtlecoin/crypto';

(async() => {
    const crypto = new Crypto();
    
    await crypto.initialize();
})
```

#### CommonJS

```javascript
const Crypto = require('turtlecoin-crypto').Crypto

(async() => {
    const crypto = new Crypto();
    
    await crypto.initialize();
})
```

#### Documentation

You can find the full TypeScript/JS documentation for this library [here](https://crypto.turtlecoin.dev).

## C++ Library

A CMakeLists.txt file enables easy builds on most systems. 

The CMake build system builds an optimized static library for you. 

However, it is best to simply include this project in your project as a dependency with your CMake project.

Please reference your system documentation on how to compile with CMake.

To use this library in your project(s) simply link against the build target (`crypto-static`) and include the following in your relevant source or header file(s).

```c++
#include <crypto.h>
```

### Documentation

C++ API documentation can be found in the headers (.h)

## Cloning this Repository

This repository uses submodules, make sure you pull those before doing anything if you are cloning this project.

```bash
git clone --recursive https://github.com/turtlecoin/turtlecoin-crypto
cd turtlecoin-crypto
```

### As a dependency
```bash
git submodule add https://github.com/turtlecoin/turtlecoin-crypto external/turtlecoin-crypto
git submodule update --init --recursive
```

## Thanks
The TurtleCoin Community


## License

External references are provided via libraries in the Public Domain (Unlicense), MIT, and/or BSD from their respective parties.

This wrapper library is provided under the BSD-3-Clause license found in the LICENSE file.

Please make sure when using this library that you follow the licensing requirements set forth in all licenses.
