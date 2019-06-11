// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

'use strict'

const assert = require('assert')
const crypto = require('../')
var testNumber = 0
const xmrigdata = '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02'

/* Hashing Tests */

console.log('')
console.log('Hashing Tests')

const cnfasthash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0'

const cnfasthashdata = crypto.cn_fast_hash(xmrigdata)

console.log('')
console.log('[#%s] cn_fast_hash: ', ++testNumber, cnfasthashdata[1])
assert.deepStrictEqual(cnfasthashdata[1], cnfasthash)

const cnslowhashv0 = '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f'
const cnslowhashv0data = crypto.cn_slow_hash_v0(xmrigdata)
console.log('[#%s] cn_slow_hash_v0: ', ++testNumber, cnslowhashv0data[1])
assert.deepStrictEqual(cnslowhashv0data[1], cnslowhashv0)

const cnslowhashv1 = 'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122'
const cnslowhashv1data = crypto.cn_slow_hash_v1(xmrigdata)
console.log('[#%s] cn_slow_hash_v1: ', ++testNumber, cnslowhashv1data[1])
assert.deepStrictEqual(cnslowhashv1data[1], cnslowhashv1)

const cnslowhashv2 = '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
const cnslowhashv2data = crypto.cn_slow_hash_v2(xmrigdata)
console.log('[#%s] cn_slow_hash_v2: ', ++testNumber, cnslowhashv2data[1])
assert.deepStrictEqual(cnslowhashv2data[1], cnslowhashv2)

const cnliteslowhashv0 = '28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd'
const cnliteslowhashv0data = crypto.cn_lite_slow_hash_v0(xmrigdata)
console.log('[#%s] cn_lite_slow_hash_v0: ', ++testNumber, cnliteslowhashv0data[1])
assert.deepStrictEqual(cnliteslowhashv0data[1], cnliteslowhashv0)

const cnliteslowhashv1 = '87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f'
const cnliteslowhashv1data = crypto.cn_lite_slow_hash_v1(xmrigdata)
console.log('[#%s] cn_lite_slow_hash_v1: ', ++testNumber, cnliteslowhashv1data[1])
assert.deepStrictEqual(cnliteslowhashv1data[1], cnliteslowhashv1)

const cnliteslowhashv2 = 'b7e78fab22eb19cb8c9c3afe034fb53390321511bab6ab4915cd538a630c3c62'
const cnliteslowhashv2data = crypto.cn_lite_slow_hash_v2(xmrigdata)
console.log('[#%s] cn_lite_slow_hash_v2: ', ++testNumber, cnliteslowhashv2data[1])
assert.deepStrictEqual(cnliteslowhashv2data[1], cnliteslowhashv2)

const cndarkslowhashv0 = 'bea42eadd78614f875e55bb972aa5ec54a5edf2dd7068220fda26bf4b1080fb8'
const cndarkslowhashv0data = crypto.cn_dark_slow_hash_v0(xmrigdata)
console.log('[#%s] cn_dark_slow_hash_v0: ', ++testNumber, cndarkslowhashv0data[1])
assert.deepStrictEqual(cndarkslowhashv0data[1], cndarkslowhashv0)

const cndarkslowhashv1 = 'd18cb32bd5b465e5a7ba4763d60f88b5792f24e513306f1052954294b737e871'
const cndarkslowhashv1data = crypto.cn_dark_slow_hash_v1(xmrigdata)
console.log('[#%s] cn_dark_slow_hash_v1: ', ++testNumber, cndarkslowhashv1data[1])
assert.deepStrictEqual(cndarkslowhashv1data[1], cndarkslowhashv1)

const cndarkslowhashv2 = 'a18a14d94efea108757a42633a1b4d4dc11838084c3c4347850d39ab5211a91f'
const cndarkslowhashv2data = crypto.cn_dark_slow_hash_v2(xmrigdata)
console.log('[#%s] cn_dark_slow_hash_v2: ', ++testNumber, cndarkslowhashv2data[1])
assert.deepStrictEqual(cndarkslowhashv2data[1], cndarkslowhashv2)

const cndarkliteslowhashv0 = 'faa7884d9c08126eb164814aeba6547b5d6064277a09fb6b414f5dbc9d01eb2b'
const cndarkliteslowhashv0data = crypto.cn_dark_lite_slow_hash_v0(xmrigdata)
console.log('[#%s] cn_dark_lite_slow_hash_v0: ', ++testNumber, cndarkliteslowhashv0data[1])
assert.deepStrictEqual(cndarkliteslowhashv0data[1], cndarkliteslowhashv0)

const cndarkliteslowhashv1 = 'c75c010780fffd9d5e99838eb093b37c0dd015101c9d298217866daa2993d277'
const cndarkliteslowhashv1data = crypto.cn_dark_lite_slow_hash_v1(xmrigdata)
console.log('[#%s] cn_dark_lite_slow_hash_v1: ', ++testNumber, cndarkliteslowhashv1data[1])
assert.deepStrictEqual(cndarkliteslowhashv1data[1], cndarkliteslowhashv1)

const cndarkliteslowhashv2 = 'fdceb794c1055977a955f31c576a8be528a0356ee1b0a1f9b7f09e20185cda28'
const cndarkliteslowhashv2data = crypto.cn_dark_lite_slow_hash_v2(xmrigdata)
console.log('[#%s] cn_dark_lite_slow_hash_v2: ', ++testNumber, cndarkliteslowhashv2data[1])
assert.deepStrictEqual(cndarkliteslowhashv2data[1], cndarkliteslowhashv2)

const cnturtleslowhashv0 = '546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982'
const cnturtleslowhashv0data = crypto.cn_turtle_slow_hash_v0(xmrigdata)
console.log('[#%s] cn_turtle_slow_hash_v0: ', ++testNumber, cnturtleslowhashv0data[1])
assert.deepStrictEqual(cnturtleslowhashv0data[1], cnturtleslowhashv0)

const cnturtleslowhashv1 = '29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e'
const cnturtleslowhashv1data = crypto.cn_turtle_slow_hash_v1(xmrigdata)
console.log('[#%s] cn_turtle_slow_hash_v1: ', ++testNumber, cnturtleslowhashv1data[1])
assert.deepStrictEqual(cnturtleslowhashv1data[1], cnturtleslowhashv1)

const cnturtleslowhashv2 = 'fc67dfccb5fc90d7855ae903361eabd76f1e40a22a72ad3ef2d6ad27b5a60ce5'
const cnturtleslowhashv2data = crypto.cn_turtle_slow_hash_v2(xmrigdata)
console.log('[#%s] cn_turtle_slow_hash_v2: ', ++testNumber, cnturtleslowhashv2data[1])
assert.deepStrictEqual(cnturtleslowhashv2data[1], cnturtleslowhashv2)

const cnturtleliteslowhashv0 = '5e1891a15d5d85c09baf4a3bbe33675cfa3f77229c8ad66c01779e590528d6d3'
const cnturtleliteslowhashv0data = crypto.cn_turtle_lite_slow_hash_v0(xmrigdata)
console.log('[#%s] cn_turtle_lite_slow_hash_v0: ', ++testNumber, cnturtleliteslowhashv0data[1])
assert.deepStrictEqual(cnturtleliteslowhashv0data[1], cnturtleliteslowhashv0)

const cnturtleliteslowhashv1 = 'ae7f864a7a2f2b07dcef253581e60a014972b9655a152341cb989164761c180a'
const cnturtleliteslowhashv1data = crypto.cn_turtle_lite_slow_hash_v1(xmrigdata)
console.log('[#%s] cn_turtle_lite_slow_hash_v1: ', ++testNumber, cnturtleliteslowhashv1data[1])
assert.deepStrictEqual(cnturtleliteslowhashv1data[1], cnturtleliteslowhashv1)

const cnturtleliteslowhashv2 = 'b2172ec9466e1aee70ec8572a14c233ee354582bcb93f869d429744de5726a26'
const cnturtleliteslowhashv2data = crypto.cn_turtle_lite_slow_hash_v2(xmrigdata)
console.log('[#%s] cn_turtle_lite_slow_hash_v2: ', ++testNumber, cnturtleliteslowhashv2data[1])
assert.deepStrictEqual(cnturtleliteslowhashv2data[1], cnturtleliteslowhashv2)

const chukwa = 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e'
const chukwadata = crypto.chukwa_slow_hash(xmrigdata)
console.log('[#%s] chukwa_slow_hash: ', ++testNumber, chukwadata[1])
assert.deepStrictEqual(chukwadata[1], chukwa)

/* Core Crypto Tests */

console.log('')
console.log('Core Crypto Tests')

const [keyError, newKeys] = crypto.generateKeys()
console.log('')
console.log('[#%s]  Key Generation Test', ++testNumber)
assert(keyError === false)
console.log('       Private Key: ', newKeys.secretKey)
console.log('       Public Key: ', newKeys.publicKey)

const testPrivateKey = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400'
const testPublicKey = '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac'

const keycheck1 = crypto.checkKey(newKeys.publicKey)
const keycheck2 = crypto.checkKey(testPublicKey)
const keycheck3 = crypto.checkKey(testPrivateKey)

console.log('')
console.log('[#%s]  Public Key Check Test', ++testNumber)
console.log('       Public Key 1: %s ', newKeys.publicKey, keycheck1)
console.log('       Public Key 2: %s ', testPublicKey, keycheck2)
console.log('       Public Key 3: %s ', testPrivateKey, keycheck3)

assert(keycheck1 === true && keycheck2 === true && keycheck3 === false)

const derivedPublicKey = crypto.secretKeyToPublicKey(testPrivateKey)

console.log('')
console.log('[#%s]  Secret Key to Public Key', ++testNumber)
console.log('       In Test Private Key: ', testPrivateKey)
console.log('       In Test Public Key: ', testPublicKey)
console.log('       Out Derived Public Key: ', derivedPublicKey[1])

assert(derivedPublicKey[1] === testPublicKey)

/* For reference, this is transaction fd9b0767c18752610833a8138e4bbb31d02b29bf50aa3af1557e2974a45c629c */
const txPublicKey = '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94'

const walletPrivateViewKey = '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909'

/* Not using this right now, but will probably need this later to test something else */
const walletPrivateSpendKey = 'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b'

const walletPublicSpendKey = '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418'

const expectedDerivation = '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20'

var [err, derivation] = crypto.generateKeyDerivation(txPublicKey, walletPrivateViewKey)

console.log('')
console.log('[#%s]  Generate Key Derivation', ++testNumber)
console.log('       Key Derivation: ', derivation)
console.log('       Expected Key Derivation: ', expectedDerivation)

assert(derivation === expectedDerivation)

const ourOutputIndex = 2

/* (First output) This is not our output. */
var publicSpendKey1
[err, publicSpendKey1] = crypto.underivePublicKey(derivation, 0, 'aae1b90b4d0a7debb417d91b7f7aa8fdfd80c42ebc6757e1449fd1618a5a3ff1')

console.log('')
console.log('[#%s]  Underive Public Key: False Test', ++testNumber)
console.log('       Derived public spend key: ', publicSpendKey1)
console.log('       Our public spend key: ', walletPublicSpendKey)

assert(publicSpendKey1 !== walletPublicSpendKey && !err)

var publicSpendKey2
[err, publicSpendKey2] = crypto.underivePublicKey(derivation, ourOutputIndex, 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')

console.log('')
console.log('[#%s]  Underive Public Key: True Test', ++testNumber)
console.log('       Derived public spend key: ', publicSpendKey2)
console.log('       Our public spend key: ', walletPublicSpendKey)

assert(publicSpendKey2 === walletPublicSpendKey && !err)

const expectedKeyImage = '5997cf23543ce2e05c327297a47f26e710af868344859a6f8d65683d8a2498b0'

var keyImage
[err, keyImage] = (() => {
  const expectedPublicKey = 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d'

  const [err1, publicKey] = crypto.derivePublicKey(derivation, ourOutputIndex, walletPublicSpendKey)

  console.log('')
  console.log('[#%s]  Derive Public Key', ++testNumber)
  console.log('       Derived Public Key: ', publicKey)
  console.log('       Expected Derived Public Key: ', expectedPublicKey)

  assert(publicKey === expectedPublicKey)

  const expectedSecretKey = 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e'

  const [err2, secretKey] = crypto.deriveSecretKey(derivation, ourOutputIndex, walletPrivateSpendKey)

  console.log('')
  console.log('[#%s]  Derive Secret Key', ++testNumber)
  console.log('       Derived Secret Key: ', secretKey)
  console.log('       Expected Derived Secret Key: ', expectedSecretKey)

  assert(secretKey === expectedSecretKey)

  assert(!err1 && !err2)

  return crypto.generateKeyImage(publicKey, secretKey)
})()

console.log('')
console.log('[#%s]  Generate KeyImage', ++testNumber)
console.log('       Generated key image: ', keyImage)
console.log('       Expected key image: ', expectedKeyImage)

assert(keyImage === expectedKeyImage && !err)
