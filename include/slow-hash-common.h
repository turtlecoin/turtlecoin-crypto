// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2014-2018, The Aeon Project
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2019, PiTi - Crypto-Webminer Project
//
// Please see the included LICENSE file for more information.

/* This file contains common CryptoNight information including
   the definitions of variants, block sizes, etc */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "int-util.h"
#include "hash-ops.h"
#include "oaes_lib.h"
#include "variant2_int_sqrt.h"
#include "variant4_random_math.h"

// Standard Crypto Definitions
#define AES_BLOCK_SIZE         16
#define AES_KEY_SIZE           32
#define INIT_SIZE_BLK          8
#define INIT_SIZE_BYTE         (INIT_SIZE_BLK * AES_BLOCK_SIZE)

extern void aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern void aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

#pragma pack(push, 1)
union cn_slow_hash_state
{
    union hash_state hs;
    struct
    {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

#define VARIANT1_1(p) \
  do if (variant == 1) \
  { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2(p) \
  do if (variant == 1) \
  { \
    xor64(p, tweak1_2); \
  } while(0)

#define VARIANT1_CHECK() \
  do if (length < 43) \
  { \
    fprintf(stderr, "Cryptonight variant 1 needs at least 43 bytes of data"); \
    abort(); \
} while(0)

#define NONCE_POINTER (((const uint8_t*)data)+35)

#define VARIANT1_PORTABLE_INIT() \
  uint8_t tweak1_2[8]; \
  do if (variant == 1) \
  { \
    VARIANT1_CHECK(); \
    memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2)); \
    xor64(tweak1_2, NONCE_POINTER); \
  } while(0)

#define VARIANT1_INIT64() \
  if (variant == 1) \
  { \
    VARIANT1_CHECK(); \
  } \
  const uint64_t tweak1_2 = (variant == 1) ? (state.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER))) : 0

#define VARIANT2_INIT64() \
  uint64_t division_result = 0; \
  uint64_t sqrt_result = 0; \
  do if (variant >= 2) \
  { \
    U64(b)[2] = state.hs.w[8] ^ state.hs.w[10]; \
    U64(b)[3] = state.hs.w[9] ^ state.hs.w[11]; \
    division_result = state.hs.w[12]; \
    sqrt_result = state.hs.w[13]; \
  } while (0)

#define VARIANT2_PORTABLE_INIT() \
  uint64_t division_result = 0; \
  uint64_t sqrt_result = 0; \
  do if (variant >= 2) \
  { \
    memcpy(b + AES_BLOCK_SIZE, state.hs.b + 64, AES_BLOCK_SIZE); \
    xor64(b + AES_BLOCK_SIZE, state.hs.b + 80); \
    xor64(b + AES_BLOCK_SIZE + 8, state.hs.b + 88); \
    division_result = SWAP64LE(state.hs.w[12]); \
    sqrt_result = SWAP64LE(state.hs.w[13]); \
  } while (0)

#define VARIANT2_SHUFFLE_ADD_SSE2(base_ptr, offset) \
  do if (variant >= 2) \
  { \
    __m128i chunk1 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))); \
    const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
    const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
    _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
    _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
    _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
    if (variant >= 4) \
    { \
      chunk1 = _mm_xor_si128(chunk1, chunk2); \
      _c = _mm_xor_si128(_c, chunk3); \
      _c = _mm_xor_si128(_c, chunk1); \
    } \
  } while (0)

#define VARIANT2_SHUFFLE_ADD_NEON(base_ptr, offset) \
  do if (variant >= 2) \
  { \
    uint64x2_t chunk1 = vld1q_u64(U64((base_ptr) + ((offset) ^ 0x10))); \
    const uint64x2_t chunk2 = vld1q_u64(U64((base_ptr) + ((offset) ^ 0x20))); \
    const uint64x2_t chunk3 = vld1q_u64(U64((base_ptr) + ((offset) ^ 0x30))); \
    vst1q_u64(U64((base_ptr) + ((offset) ^ 0x10)), vaddq_u64(chunk3, vreinterpretq_u64_u8(_b1))); \
    vst1q_u64(U64((base_ptr) + ((offset) ^ 0x20)), vaddq_u64(chunk1, vreinterpretq_u64_u8(_b))); \
    vst1q_u64(U64((base_ptr) + ((offset) ^ 0x30)), vaddq_u64(chunk2, vreinterpretq_u64_u8(_a))); \
    if (variant >= 4) \
    { \
      chunk1 = veorq_u64(chunk1, chunk2); \
      _c = vreinterpretq_u8_u64(veorq_u64(vreinterpretq_u64_u8(_c), chunk3)); \
      _c = vreinterpretq_u8_u64(veorq_u64(vreinterpretq_u64_u8(_c), chunk1)); \
    } \
  } while (0)

#define VARIANT2_PORTABLE_SHUFFLE_ADD(out, a_, base_ptr, offset) \
  do if (variant >= 2) \
  { \
    uint64_t* chunk1 = U64((base_ptr) + ((offset) ^ 0x10)); \
    uint64_t* chunk2 = U64((base_ptr) + ((offset) ^ 0x20)); \
    uint64_t* chunk3 = U64((base_ptr) + ((offset) ^ 0x30)); \
    \
    uint64_t chunk1_old[2] = { SWAP64LE(chunk1[0]), SWAP64LE(chunk1[1]) }; \
    const uint64_t chunk2_old[2] = { SWAP64LE(chunk2[0]), SWAP64LE(chunk2[1]) }; \
    const uint64_t chunk3_old[2] = { SWAP64LE(chunk3[0]), SWAP64LE(chunk3[1]) }; \
    \
    uint64_t b1[2]; \
    memcpy_swap64le(b1, b + 16, 2); \
    chunk1[0] = SWAP64LE(chunk3_old[0] + b1[0]); \
    chunk1[1] = SWAP64LE(chunk3_old[1] + b1[1]); \
    \
    uint64_t a0[2]; \
    memcpy_swap64le(a0, a_, 2); \
    chunk3[0] = SWAP64LE(chunk2_old[0] + a0[0]); \
    chunk3[1] = SWAP64LE(chunk2_old[1] + a0[1]); \
    \
    uint64_t b0[2]; \
    memcpy_swap64le(b0, b, 2); \
    chunk2[0] = SWAP64LE(chunk1_old[0] + b0[0]); \
    chunk2[1] = SWAP64LE(SWAP64LE(chunk1_old[1]) + b0[1]); \
    if (variant >= 4) \
    { \
      uint64_t out_copy[2]; \
      memcpy_swap64le(out_copy, out, 2); \
      chunk1_old[0] ^= chunk2_old[0]; \
      chunk1_old[1] ^= chunk2_old[1]; \
      out_copy[0] ^= chunk3_old[0]; \
      out_copy[1] ^= chunk3_old[1]; \
      out_copy[0] ^= chunk1_old[0]; \
      out_copy[1] ^= chunk1_old[1]; \
      memcpy_swap64le(out, out_copy, 2); \
    } \
  } while (0)

#define VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr) \
  uint64_t tmpx = division_result ^ (sqrt_result << 32); \
  ((uint64_t*)(b))[0] ^= SWAP64LE(tmpx); \
  { \
    const uint64_t dividend = SWAP64LE(((uint64_t*)(ptr))[1]); \
    const uint32_t divisor = (SWAP64LE(((uint64_t*)(ptr))[0]) + (uint32_t)(sqrt_result << 1)) | 0x80000001UL; \
    division_result = ((uint32_t)(dividend / divisor)) + \
                     (((uint64_t)(dividend % divisor)) << 32); \
  } \
  const uint64_t sqrt_input = SWAP64LE(((uint64_t*)(ptr))[0]) + division_result

#define VARIANT2_INTEGER_MATH_SSE2(b, ptr) \
  do if ((variant == 2) || (variant == 3)) \
  { \
    VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr); \
    VARIANT2_INTEGER_MATH_SQRT_STEP_SSE2(); \
    VARIANT2_INTEGER_MATH_SQRT_FIXUP(sqrt_result); \
  } while(0)

#if defined DBL_MANT_DIG && (DBL_MANT_DIG >= 50)
  // double precision floating point type has enough bits of precision on current platform
  #define VARIANT2_PORTABLE_INTEGER_MATH(b, ptr) \
    do if ((variant == 2) || (variant == 3)) \
    { \
      VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr); \
      VARIANT2_INTEGER_MATH_SQRT_STEP_FP64(); \
      VARIANT2_INTEGER_MATH_SQRT_FIXUP(sqrt_result); \
    } while (0)
#else
  // double precision floating point type is not good enough on current platform
  // fall back to the reference code (integer only)
  #define VARIANT2_PORTABLE_INTEGER_MATH(b, ptr) \
    do if ((variant == 2) || (variant == 3)) \
    { \
      VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr); \
      VARIANT2_INTEGER_MATH_SQRT_STEP_REF(); \
    } while (0)
#endif

#define VARIANT2_2_PORTABLE() \
    if (variant == 2 || variant == 3) { \
      xor_blocks(long_state + (j ^ 0x10), d); \
      xor_blocks(d, long_state + (j ^ 0x20)); \
    }

#define VARIANT2_2() \
  do if (variant == 2 || variant == 3) \
  { \
    *U64(hp_state + (j ^ 0x10)) ^= SWAP64LE(hi); \
    *(U64(hp_state + (j ^ 0x10)) + 1) ^= SWAP64LE(lo); \
    hi ^= SWAP64LE(*U64(hp_state + (j ^ 0x20))); \
    lo ^= SWAP64LE(*(U64(hp_state + (j ^ 0x20)) + 1)); \
  } while (0)

#define V4_REG_LOAD(dst, src) \
  do { \
    memcpy((dst), (src), sizeof(v4_reg)); \
    if (sizeof(v4_reg) == sizeof(uint32_t)) \
      *(dst) = SWAP32LE(*(dst)); \
    else \
      *(dst) = SWAP64LE(*(dst)); \
  } while (0)

#define VARIANT4_RANDOM_MATH_INIT() \
  v4_reg r[9]; \
  struct V4_Instruction code[NUM_INSTRUCTIONS_MAX + 1]; \
  do if (variant >= 4) \
  { \
    for (int i = 0; i < 4; ++i) \
      V4_REG_LOAD(r + i, (uint8_t*)(state.hs.w + 12) + sizeof(v4_reg) * i); \
    v4_random_math_init(code, height); \
  } while (0)

#define VARIANT4_RANDOM_MATH(a, b, r, _b, _b1) \
  do if (variant >= 4) \
  { \
    uint64_t tmp[2]; \
    memcpy(tmp, b, sizeof(uint64_t)); \
    \
    if (sizeof(v4_reg) == sizeof(uint32_t)) \
      tmp[0] ^= SWAP64LE((r[0] + r[1]) | ((uint64_t)(r[2] + r[3]) << 32)); \
    else \
      tmp[0] ^= SWAP64LE((r[0] + r[1]) ^ (r[2] + r[3])); \
    \
    memcpy(b, tmp, sizeof(uint64_t)); \
    \
    V4_REG_LOAD(r + 4, a); \
    V4_REG_LOAD(r + 5, (uint64_t*)(a) + 1); \
    V4_REG_LOAD(r + 6, _b); \
    V4_REG_LOAD(r + 7, _b1); \
    V4_REG_LOAD(r + 8, (uint64_t*)(_b1) + 1); \
    \
    v4_random_math(code, r); \
    \
    memcpy(tmp, a, sizeof(uint64_t) * 2); \
    \
    if (sizeof(v4_reg) == sizeof(uint32_t)) { \
      tmp[0] ^= SWAP64LE(r[2] | ((uint64_t)(r[3]) << 32)); \
      tmp[1] ^= SWAP64LE(r[0] | ((uint64_t)(r[1]) << 32)); \
    } else { \
      tmp[0] ^= SWAP64LE(r[2] ^ r[3]); \
      tmp[1] ^= SWAP64LE(r[0] ^ r[1]); \
    } \
    memcpy(a, tmp, sizeof(uint64_t) * 2); \
} while (0)
