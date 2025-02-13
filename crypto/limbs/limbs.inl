/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "../internal.h"
#include "limbs.h"
#include "ring-core/check.h"

#if defined(__has_builtin)
#define RING_HAS_BUILTIN(b) __has_builtin(b)
#else
#define RING_HAS_BUILTIN(b) 0
#endif

#if RING_HAS_BUILTIN(__builtin_addcll)

#define RING_USE_BUILTINS
typedef Limb Carry;

#elif defined(OPENSSL_X86) || defined(OPENSSL_X86_64)

#if defined(_MSC_VER) && !defined(__clang__)
/* MSVC 2015 RC, when compiling for x86 with /Ox (at least), miscompiles
 * _addcarry_u32(c, 0, prod_hi, &x) like so:
 *
 *     add eax,esi ; The previous add that might have set the carry flag.
 *     xor esi,esi ; OOPS! Carry flag is now reset!
 *     mov dword ptr [edi-4],eax
 *     adc esi,dword ptr [prod_hi]
 *
 * We test with MSVC 2015 update 2, so make sure we're using a version at least
 * as new as that. */
#if _MSC_FULL_VER < 190023918
#error "MSVC 2015 Update 2 or later is required."
#endif

#pragma warning(push, 3)
#endif

#include <immintrin.h>


#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(pop)
#endif

#define RING_USE_X86_INTRINSICS 1
typedef uint8_t Carry;

#else

typedef Limb Carry;

#if LIMB_BITS == 64
typedef __uint128_t DoubleLimb;
#elif LIMB_BITS == 32
typedef uint64_t DoubleLimb;
#endif

#endif

/* |*r = a + b + carry_in|, returning carry out bit. |carry_in| must be 0 or 1.
 */
static inline Carry limb_adc(Limb *r, Limb a, Limb b, Carry carry_in) {
  dev_assert_secret(carry_in == 0 || carry_in == 1);
  Carry ret;
#if (LIMB_BITS == 64) && defined(RING_USE_BUILTINS)
  *r = __builtin_addcll(a, b, carry_in, (unsigned long long *)&ret);
#elif (LIMB_BITS == 64) && defined(RING_USE_X86_INTRINSICS)
  ret = _addcarry_u64(carry_in, a, b, (void *) r);
#elif (LIMB_BITS == 32) && defined(RING_USE_BUILTINS)
  *r = __builtin_addcl(a, b, carry_in, &ret);
#elif (LIMB_BITS == 32) && defined(RING_USE_X86_INTRINSICS)
  ret = _addcarry_u32(carry_in, a, b, (void *) r);
#else
  DoubleLimb x = (DoubleLimb)a + b + carry_in;
  *r = (Limb)x;
  ret = (Carry)(x >> LIMB_BITS);
#endif
  dev_assert_secret(ret == 0 || ret == 1);
  return ret;
}

/* |*r = a - b - borrow_in|, returning the borrow out bit. |borrow_in| must be
 * 0 or 1. */
static inline Carry limb_sbb(Limb *r, Limb a, Limb b, Carry borrow_in) {
  dev_assert_secret(borrow_in == 0 || borrow_in == 1);
  Carry ret;
#if (LIMB_BITS == 64) && defined(RING_USE_BUILTINS)
  *r = __builtin_subcll(a, b, borrow_in, (unsigned long long *)&ret);
#elif (LIMB_BITS == 64) && defined(RING_USE_X86_INTRINSICS)
  ret = _subborrow_u64(borrow_in, a, b, (void *) r);
#elif (LIMB_BITS == 32) && defined(RING_USE_BUILTINS)
  *r = __builtin_subcl(a, b, borrow_in, &ret);
#elif (LIMB_BITS == 32) && defined(RING_USE_X86_INTRINSICS)
  ret = _subborrow_u32(borrow_in, a, b, (void *) r);
#else
  DoubleLimb x = (DoubleLimb)a - b - borrow_in;
  *r = (Limb)x;
  ret = (Carry)((x >> LIMB_BITS) & 1);
#endif
  dev_assert_secret(ret == 0 || ret == 1);
  return ret;
}

/* |*r = a - b|, returning borrow bit. */
static inline Carry limb_add(Limb *r, Limb a, Limb b) {
  return limb_adc(r, a, b, 0);
}

/* |*r = a - b|, returning borrow bit. */
static inline Carry limb_sub(Limb *r, Limb a, Limb b) {
  return limb_sbb(r, a, b, 0);
}

static inline Carry limbs_add(Limb r[], const Limb a[], const Limb b[],
                              size_t num_limbs) {
  debug_assert_nonsecret(num_limbs >= 1);
  Carry carry = limb_add(&r[0], a[0], b[0]);
  for (size_t i = 1; i < num_limbs; ++i) {
    carry = limb_adc(&r[i], a[i], b[i], carry);
  }
  return carry;
}

/* |r -= s|, returning the borrow. */
static inline Carry limbs_sub(Limb r[], const Limb a[], const Limb b[],
                              size_t num_limbs) {
  debug_assert_nonsecret(num_limbs >= 1);
  Carry borrow = limb_sub(&r[0], a[0], b[0]);
  for (size_t i = 1; i < num_limbs; ++i) {
    borrow = limb_sbb(&r[i], a[i], b[i], borrow);
  }
  return borrow;
}

static inline void limbs_copy(Limb r[], const Limb a[], size_t num_limbs) {
  for (size_t i = 0; i < num_limbs; ++i) {
    r[i] = a[i];
  }
}

static inline void limbs_select(Limb r[], const Limb table[],
                                size_t num_limbs, size_t num_entries,
                                crypto_word_t index) {
  for (size_t i = 0; i < num_limbs; ++i) {
    r[i] = 0;
  }

  for (size_t e = 0; e < num_entries; ++e) {
    Limb equal = constant_time_eq_w(index, e);
    for (size_t i = 0; i < num_limbs; ++i) {
      r[i] = constant_time_select_w(equal, table[(e * num_limbs) + i], r[i]);
    }
  }
}

static inline void limbs_zero(Limb r[], size_t num_limbs) {
  for (size_t i = 0; i < num_limbs; ++i) {
    r[i] = 0;
  }
}
