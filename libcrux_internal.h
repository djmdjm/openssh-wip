/*  $OpenBSD$ */

/* Extracted from libcrux revision 46cab2e6de2b364d02f89f4f0b62356d846b11a2 */

/*
 * MIT License
 *
 * Copyright (c) 2024 Cryspen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif
#define KRML_MUSTINLINE inline
#define KRML_NOINLINE __attribute__((noinline, unused))
#define KRML_HOST_EPRINTF(...)
#define KRML_HOST_EXIT(x) fatal_f("internal error")
#define KRML_UNION_CONSTRUCTOR(T)

static inline void
store64_le(uint8_t dst[8], uint64_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
	dst[4] = (src >> 32) & 0xff;
	dst[5] = (src >> 40) & 0xff;
	dst[6] = (src >> 48) & 0xff;
	dst[7] = (src >> 56) & 0xff;
}

static inline void
store32_le(uint8_t dst[4], uint32_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
}

static inline void
store32_be(uint8_t dst[4], uint32_t src)
{
	dst[0] = (src >> 24) & 0xff;
	dst[1] = (src >> 16) & 0xff;
	dst[2] = (src >> 8) & 0xff;
	dst[3] = src & 0xff;
}

static inline uint64_t
load64_le(uint8_t src[8])
{
	return (uint64_t)(src[0]) |
	    ((uint64_t)(src[1]) << 8) |
	    ((uint64_t)(src[2]) << 16) |
	    ((uint64_t)(src[3]) << 24) |
	    ((uint64_t)(src[4]) << 32) |
	    ((uint64_t)(src[5]) << 40) |
	    ((uint64_t)(src[6]) << 48) |
	    ((uint64_t)(src[7]) << 56);
}

static inline uint32_t
load32_le(uint8_t src[4])
{
	return (uint32_t)(src[0]) |
	    ((uint32_t)(src[1]) << 8) |
	    ((uint32_t)(src[2]) << 16) |
	    ((uint32_t)(src[3]) << 24);
}

#ifdef MISSING_BUILTIN_POPCOUNT
static inline unsigned int
__builtin_popcount(unsigned int num)
{
  const int v[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
  return v[num & 0xf] + v[(num >> 4) & 0xf];
}
#endif

/* from libcrux/combined_extraction/generated/eurydice_glue.h */
/*
 * SPDX-FileCopyrightText: 2024 Eurydice Contributors
 * SPDX-FileCopyrightText: 2024-2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 */

#pragma once


#ifdef _MSC_VER
// For __popcnt
#endif


// C++ HELPERS

#if defined(__cplusplus)


#ifndef __cpp_lib_type_identity
template <class T>
struct type_identity {
  using type = T;
};

template <class T>
using type_identity_t = typename type_identity<T>::type;
#else
using std::type_identity_t;
#endif

#define KRML_UNION_CONSTRUCTOR(T)                              \
  template <typename V>                                        \
  constexpr T(int t, V U::*m, type_identity_t<V> v) : tag(t) { \
    val.*m = std::move(v);                                     \
  }                                                            \
  T() = default;

#endif

// GENERAL-PURPOSE STUFF

#define LowStar_Ignore_ignore(e, t, _ret_t) ((void)e)

#define EURYDICE_ASSERT(test, msg)                                            \
  do {                                                                        \
    if (!(test)) {                                                            \
      fprintf(stderr, "assertion \"%s\" failed: file \"%s\", line %d\n", msg, \
              __FILE__, __LINE__);                                            \
    }                                                                         \
  } while (0)

// SLICES, ARRAYS, ETC.

// We represent a slice as a pair of an (untyped) pointer, along with the length
// of the slice, i.e. the number of elements in the slice (this is NOT the
// number of bytes). This design choice has two important consequences.
// - if you need to use `ptr`, you MUST cast it to a proper type *before*
//   performing pointer arithmetic on it (remember that C desugars pointer
//   arithmetic based on the type of the address)
// - if you need to use `len` for a C style function (e.g. memcpy, memcmp), you
//   need to multiply it by sizeof t, where t is the type of the elements.
//
// Empty slices have `len == 0` and `ptr` always needs to be a valid pointer
// that is not NULL (otherwise the construction in EURYDICE_SLICE computes `NULL
// + start`).
typedef struct {
  void *ptr;
  size_t len;
} Eurydice_slice;

typedef struct Eurydice_dst_ref_87_s {
  uint8_t *ptr;
  size_t meta;
} Eurydice_dst_ref_87;

typedef struct Eurydice_dst_ref_9a_s {
  int16_t *ptr;
  size_t meta;
} Eurydice_dst_ref_9a;

#if defined(__cplusplus)
#define KRML_CLITERAL(type) type
#else
#define KRML_CLITERAL(type) (type)
#endif

#if defined(__cplusplus) && defined(__cpp_designated_initializers) || \
    !(defined(__cplusplus))
#define EURYDICE_CFIELD(X) X
#else
#define EURYDICE_CFIELD(X)
#endif

// Helper macro to create a slice out of a pointer x, a start index in x
// (included), and an end index in x (excluded). The argument x must be suitably
// cast to something that can decay (see remark above about how pointer
// arithmetic works in C), meaning either pointer or array type.
#define EURYDICE_SLICE(x, start, end) \
  (KRML_CLITERAL(Eurydice_slice){(void *)(x + start), end - start})

// Slice length
#define EURYDICE_SLICE_LEN(s, _) (s).meta
#define Eurydice_slice_len(s, _) (s).meta

#define Eurydice_slice_index_mut(s, i, t) ((s).ptr[i])
#define Eurydice_slice_index_shared(s, i, t) ((s).ptr[i])

#define Eurydice_slice_index(s, i, t) ((s).ptr[i])

// The following functions get sub slices from a slice.

#define Eurydice_slice_subslice(s, r, t, _0, _1) \
  EURYDICE_SLICE((t *)s.ptr, r.start, r.end)

// Variant for when the start and end indices are statically known (i.e., the
// range argument `r` is a literal).
#define Eurydice_slice_subslice2(s, start, end, t) \
  EURYDICE_SLICE((t *)s.ptr, (start), (end))

// Previous version above does not work when t is an array type (as usual). Will
// be deprecated soon.
#define Eurydice_slice_subslice3(s, start, end, t_ptr) \
  EURYDICE_SLICE((t_ptr)s.ptr, (start), (end))

#define Eurydice_slice_subslice_to(s, subslice_end_pos, t, _0, _1) \
  EURYDICE_SLICE((t *)s.ptr, 0, subslice_end_pos)

#define Eurydice_slice_subslice_from(s, subslice_start_pos, t, _0, _1) \
  EURYDICE_SLICE((t *)s.ptr, subslice_start_pos, s.len)

#define Eurydice_array_to_slice(end, x, t) \
  EURYDICE_SLICE(x, 0,                     \
                 end) /* x is already at an array type, no need for cast */
#define Eurydice_array_to_subslice(_arraylen, x, r, t, _0, _1) \
  EURYDICE_SLICE((t *)x, r.start, r.end)

// Same as above, variant for when start and end are statically known
#define Eurydice_array_to_subslice2(x, start, end, t) \
  EURYDICE_SLICE((t *)x, (start), (end))

// Same as above, variant for when start and end are statically known
#define Eurydice_array_to_subslice3(x, start, end, t_ptr) \
  EURYDICE_SLICE((t_ptr)x, (start), (end))
// The following functions convert an array into a slice.

#define Eurydice_array_to_subslice_to(_size, x, r, t, _range_t, _0) \
  EURYDICE_SLICE((t *)x, 0, r)
#define Eurydice_array_to_subslice_from(size, x, r, t, _range_t, _0) \
  EURYDICE_SLICE((t *)x, r, size)

// Copy a slice with memcopy
#define Eurydice_slice_copy(dst, src, t) \
  memcpy(dst.ptr, src.ptr, dst.meta * sizeof(t))

// Distinguished support for some PartialEq trait implementations
//
#define Eurydice_slice_eq(src1, src2, t, _) \
  ((src1)->len == (src2)->len &&            \
   !memcmp((src1)->ptr, (src2)->ptr, (src1)->len * sizeof(t)))

#define core_array___Array_T__N___as_slice(len_, ptr_, t, ret_t) \
  (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ptr =)(ptr_)->data,     \
                        EURYDICE_CFIELD(.meta =) len_})

#define core_array__core__clone__Clone_for__Array_T__N___clone( \
    len, src, elem_type, _ret_t)                                \
  (*src)
#define TryFromSliceError uint8_t

#define Eurydice_array_eq(sz, a1, a2, t) (memcmp(a1, a2, sz * sizeof(t)) == 0)

// core::cmp::PartialEq<&0 (@Slice<U>)> for @Array<T, N>
#define Eurydice_array_eq_slice(sz, a1, s2, t, _) \
  (memcmp(a1, (s2)->ptr, sz * sizeof(t)) == 0)

#define Eurydice_array_eq_slice_shared(sz, a1, s2, t, _)   \
  (memcmp(a1, (s2)->ptr, sz * sizeof(t)) == 0)

#define core_array_equality___core__cmp__PartialEq__Array_U__N___for__Array_T__N____eq( \
    sz, a1, a2, t, _, _ret_t)                                                           \
  Eurydice_array_eq(sz, a1, a2, t, _)

#define core_array_equality___core__cmp__PartialEq__0___Slice_U____for__Array_T__N___3__eq( \
    sz, a1, a2, t, _, _ret_t)                                                               \
  Eurydice_array_eq(sz, a1, ((a2)->ptr), t, _)

#define Eurydice_slice_split_at(slice, mid, element_type, ret_t)        \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((slice).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((slice).ptr + mid), EURYDICE_CFIELD(.meta =)((slice).meta - mid) \
    }                                                                   \
  }

#define Eurydice_slice_split_at_mut(slice, mid, element_type, ret_t)  \
  KRML_CLITERAL(ret_t) {                                              \
    EURYDICE_CFIELD(.fst =)                                           \
    KRML_CLITERAL(Eurydice_slice){EURYDICE_CFIELD(.ptr =)(slice.ptr), \
                                  EURYDICE_CFIELD(.len =) mid},       \
        EURYDICE_CFIELD(.snd =) KRML_CLITERAL(Eurydice_slice) {       \
      EURYDICE_CFIELD(.ptr =)                                         \
      ((char *)slice.ptr + mid * sizeof(element_type)),               \
          EURYDICE_CFIELD(.len =)(slice.len - mid)                    \
    }                                                                 \
  }

// Conversion of slice to an array, rewritten (by Eurydice) to name the
// destination array, since arrays are not values in C.
// N.B.: see note in karamel/lib/Inlining.ml if you change this.
#define Eurydice_slice_to_array2(dst, src, _0, t_arr, _1)                 \
  Eurydice_slice_to_array3(&(dst)->tag, (char *)&(dst)->val.case_Ok, src, \
                           sizeof(t_arr))

static KRML_MUSTINLINE void Eurydice_slice_to_array3(uint8_t *dst_tag,
                                                     char *dst_ok,
                                                     Eurydice_slice src,
                                                     size_t sz) {
  *dst_tag = 0;
  memcpy(dst_ok, src.ptr, sz);
}

// CORE STUFF (conversions, endianness, ...)

typedef struct Eurydice_arr_8b_s {
  uint8_t data[2];
} Eurydice_arr_8b;

// [ u8; 2 ]
typedef struct Eurydice_array_u8x2_s {
  uint8_t data[2];
} Eurydice_array_u8x2;

// [ u8; 8 ]
typedef struct Eurydice_array_u8x8_s {
  uint8_t data[8];
} Eurydice_array_u8x8;

// &mut [u8]
typedef struct Eurydice_mut_borrow_slice_u8_s {
  uint8_t *ptr;
  size_t meta;
} Eurydice_mut_borrow_slice_u8;

// &[u8]
typedef struct Eurydice_borrow_slice_u8_s {
  const uint8_t *ptr;
  size_t meta;
} Eurydice_borrow_slice_u8;

// &mut [i16]
typedef struct Eurydice_mut_borrow_slice_16_s {
  int16_t *ptr;
  size_t meta;
} Eurydice_mut_borrow_slice_i16;

// &[i16]
typedef struct Eurydice_borrow_slice_i16_s {
  const int16_t *ptr;
  size_t meta;
} Eurydice_borrow_slice_i16;

static inline Eurydice_array_u8x8 core_num__u64__to_le_bytes(uint64_t v) {
  Eurydice_array_u8x8 a;
  store64_le(a.data, v);
  return a;
}

static inline uint64_t core_num__u64__from_le_bytes(Eurydice_array_u8x8 buf) {
  return load64_le(buf.data);
}

static KRML_MUSTINLINE uint32_t core_num__u32__from_le_bytes(uint8_t buf[4]) {
  return load32_le(buf);
}

static KRML_MUSTINLINE uint32_t core_num__u8__count_ones(uint8_t x0) {
#ifdef _MSC_VER
  return __popcnt(x0);
#else
  return __builtin_popcount(x0);
#endif
}

static inline uint32_t core_num__i32__count_ones(int32_t x0) {
#ifdef _MSC_VER
  return __popcnt(x0);
#else
  return __builtin_popcount(x0);
#endif
}

static inline uint8_t Eurydice_bitand_pv_u8(const uint8_t *p, uint8_t v) {
  return (*p) & v;
}
static inline uint8_t Eurydice_shr_pv_u8(const uint8_t *p, int32_t v) {
  return (*p) >> v;
}

static inline uint8_t
core_ops_bit__core__ops__bit__BitAnd_u8__u8__for__0__u8___bitand(
    const uint8_t *x0, uint8_t x1) {
  return Eurydice_bitand_pv_u8(x0, x1);
}

static inline uint8_t
core_ops_bit__core__ops__bit__Shr_i32__u8__for__0__u8___shr(const uint8_t *x0,
                                                            int32_t x1) {
  return Eurydice_shr_pv_u8(x0, x1);
}

// unsigned overflow wraparound semantics in C
static KRML_MUSTINLINE uint16_t core_num__u16__wrapping_add(uint16_t x,
                                                            uint16_t y) {
  return x + y;
}
static KRML_MUSTINLINE uint8_t core_num__u8__wrapping_sub(uint8_t x,
                                                          uint8_t y) {
  return x - y;
}

static KRML_MUSTINLINE uint64_t core_num__u64__rotate_left(uint64_t x0,
                                                           uint32_t x1) {
  return (x0 << x1 | x0 >> (64 - x1));
}

// ITERATORS

#define Eurydice_range_iter_next(iter_ptr, t, ret_t)      \
  (((iter_ptr)->start >= (iter_ptr)->end)                 \
       ? (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.tag =) 0, \
                               EURYDICE_CFIELD(.f0 =) 0}) \
       : (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.tag =) 1, \
                               EURYDICE_CFIELD(.f0 =)(iter_ptr)->start++}))

#define core_iter_range___core__iter__traits__iterator__Iterator_A__for_core__ops__range__Range_A__TraitClause_0___6__next \
  Eurydice_range_iter_next

// See note in karamel/lib/Inlining.ml if you change this
#define Eurydice_into_iter(x, t, _ret_t, _) (x)
#define core_iter_traits_collect___core__iter__traits__collect__IntoIterator_Clause1_Item__I__for_I__1__into_iter \
  Eurydice_into_iter

// OPTIONS

#define core_option__core__option__Option_T__TraitClause_0___is_some( \
    x, _of_type, _)                                                   \
  x->tag

/* from libcrux/combined_extraction/generated/libcrux_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_core_H
#define libcrux_core_H




static inline uint32_t core_num__i32__count_ones(int32_t x0);

static inline uint16_t core_num__u16__wrapping_add(uint16_t x0, uint16_t x1);

static inline uint64_t core_num__u64__from_le_bytes(Eurydice_array_u8x8 x0);

static inline uint64_t core_num__u64__rotate_left(uint64_t x0, uint32_t x1);

static inline Eurydice_array_u8x8 core_num__u64__to_le_bytes(uint64_t x0);

static inline uint32_t core_num__u8__count_ones(uint8_t x0);

static inline uint8_t core_num__u8__wrapping_sub(uint8_t x0, uint8_t x1);

static inline uint8_t
core_ops_bit__core__ops__bit__BitAnd_u8__u8__for__0__u8___bitand(const uint8_t *x0, uint8_t x1);

static inline uint8_t
core_ops_bit__core__ops__bit__Shr_i32__u8__for__0__u8___shr(const uint8_t *x0, int32_t x1);

/**
A monomorphic instance of core.ops.range.Range
with types size_t

*/
typedef struct core_ops_range_Range_08_s
{
  size_t start;
  size_t end;
}
core_ops_range_Range_08;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
static inline Eurydice_mut_borrow_slice_i16
Eurydice_slice_subslice_mut_76(Eurydice_mut_borrow_slice_i16 s, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_i16){ s.ptr + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $16size_t
*/
typedef struct Eurydice_arr_88_s { uint8_t data[16U]; } Eurydice_arr_88;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_88
with const generics
- $256size_t
*/
typedef struct Eurydice_arr_e60_s { Eurydice_arr_88 data[256U]; } Eurydice_arr_e60;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $24size_t
*/
typedef struct Eurydice_arr_6d_s { uint8_t data[24U]; } Eurydice_arr_6d;

#define Ok 0
#define Err 1

typedef uint8_t Result_80_tags;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_6d, core_array_TryFromSliceError

*/
typedef struct Result_80_s
{
  Result_80_tags tag;
  union {
    Eurydice_arr_6d case_Ok;
    TryFromSliceError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_80_s)
}
Result_80;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$24size_t]], core_array_TryFromSliceError

*/
static inline Eurydice_arr_6d unwrap_26_a9(Result_80 self)
{
  if (self.tag == Ok)
  {
    return self.val.case_Ok;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $16size_t
*/
typedef struct Eurydice_arr_e2_s { int16_t data[16U]; } Eurydice_arr_e2;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $20size_t
*/
typedef struct Eurydice_arr_dc_s { uint8_t data[20U]; } Eurydice_arr_dc;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_dc, core_array_TryFromSliceError

*/
typedef struct Result_fe_s
{
  Result_80_tags tag;
  union {
    Eurydice_arr_dc case_Ok;
    TryFromSliceError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_fe_s)
}
Result_fe;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$20size_t]], core_array_TryFromSliceError

*/
static inline Eurydice_arr_dc unwrap_26_51(Result_fe self)
{
  if (self.tag == Ok)
  {
    return self.val.case_Ok;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1184size_t
*/
typedef struct Eurydice_arr_74_s { uint8_t data[1184U]; } Eurydice_arr_74;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_8c2(const Eurydice_arr_74 *a, size_t r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r, (size_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_to_shared_6e0(const Eurydice_arr_74 *a, size_t r)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = r;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2400size_t
*/
typedef struct Eurydice_arr_ea_s { uint8_t data[2400U]; } Eurydice_arr_ea;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_368(const Eurydice_arr_ea *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1152size_t
*/
typedef struct Eurydice_arr_60_s { uint8_t data[1152U]; } Eurydice_arr_60;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1152
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_06(const Eurydice_arr_60 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1152U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3617(Eurydice_arr_ea *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1152
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_06(Eurydice_arr_60 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1152U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_8c4(Eurydice_arr_74 *a, size_t r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r, (size_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3616(Eurydice_arr_74 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 24
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_0b(const Eurydice_arr_6d *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)24U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $384size_t
*/
typedef struct Eurydice_arr_cc_s { uint8_t data[384U]; } Eurydice_arr_cc;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 384
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3615(Eurydice_arr_cc *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 384
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_fe(const Eurydice_arr_cc *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)384U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $32size_t
*/
typedef struct Eurydice_arr_600_s { uint8_t data[32U]; } Eurydice_arr_600;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_600, core_array_TryFromSliceError

*/
typedef struct Result_fd_s
{
  Result_80_tags tag;
  union {
    Eurydice_arr_600 case_Ok;
    TryFromSliceError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_fd_s)
}
Result_fd;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$32size_t]], core_array_TryFromSliceError

*/
static inline Eurydice_arr_600 unwrap_26_07(Result_fd self)
{
  if (self.tag == Ok)
  {
    return self.val.case_Ok;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $64size_t
*/
typedef struct Eurydice_arr_060_s { uint8_t data[64U]; } Eurydice_arr_060;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_8c1(const Eurydice_arr_060 *a, size_t r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r, (size_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_367(const Eurydice_arr_060 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1184
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_45(const Eurydice_arr_74 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1184U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1088size_t
*/
typedef struct Eurydice_arr_2c_s { uint8_t data[1088U]; } Eurydice_arr_2c;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_8c3(Eurydice_arr_2c *a, size_t r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r, (size_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3614(Eurydice_arr_2c *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 20
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_c2(const Eurydice_arr_dc *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)20U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $320size_t
*/
typedef struct Eurydice_arr_b70_s { uint8_t data[320U]; } Eurydice_arr_b70;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 320
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3613(Eurydice_arr_b70 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 320
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_d3(const Eurydice_arr_b70 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)320U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $256size_t
*/
typedef struct Eurydice_arr_c1_s { int16_t data[256U]; } Eurydice_arr_c1;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int16_t
with const generics
- N= 256
*/
static inline Eurydice_borrow_slice_i16
Eurydice_array_to_slice_shared_1a(const Eurydice_arr_c1 *a)
{
  Eurydice_borrow_slice_i16 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)256U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $128size_t
*/
typedef struct Eurydice_arr_d1_s { uint8_t data[128U]; } Eurydice_arr_d1;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_d1
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_ad0_s { Eurydice_arr_d1 data[3U]; } Eurydice_arr_ad0;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $33size_t
*/
typedef struct Eurydice_arr_3e0_s { uint8_t data[33U]; } Eurydice_arr_3e0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 33
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_61(const Eurydice_arr_3e0 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)33U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_3e0
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_b1_s { Eurydice_arr_3e0 data[3U]; } Eurydice_arr_b1;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 33
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3612(Eurydice_arr_3e0 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $272size_t
*/
typedef struct Eurydice_arr_a00_s { int16_t data[272U]; } Eurydice_arr_a00;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
static inline Eurydice_borrow_slice_i16
Eurydice_array_to_subslice_shared_850(const Eurydice_arr_a00 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_i16){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $168size_t
*/
typedef struct Eurydice_arr_27_s { uint8_t data[168U]; } Eurydice_arr_27;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_366(const Eurydice_arr_27 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_27
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_7e_s { Eurydice_arr_27 data[3U]; } Eurydice_arr_7e;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_a00
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_dd1_s { Eurydice_arr_a00 data[3U]; } Eurydice_arr_dd1;

/**
A monomorphic instance of Eurydice.arr
with types size_t
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_c8_s { size_t data[3U]; } Eurydice_arr_c8;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
static inline Eurydice_mut_borrow_slice_i16
Eurydice_array_to_subslice_mut_85(Eurydice_arr_a00 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_i16){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $504size_t
*/
typedef struct Eurydice_arr_b00_s { uint8_t data[504U]; } Eurydice_arr_b00;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 504
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_365(const Eurydice_arr_b00 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b00
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_e6_s { Eurydice_arr_b00 data[3U]; } Eurydice_arr_e6;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 504
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_85(Eurydice_arr_b00 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)504U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $34size_t
*/
typedef struct Eurydice_arr_48_s { uint8_t data[34U]; } Eurydice_arr_48;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_48
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_c31_s { Eurydice_arr_48 data[3U]; } Eurydice_arr_c31;

/**
A monomorphic instance of Eurydice.slice_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t

*/
static inline Eurydice_borrow_slice_u8
Eurydice_slice_subslice_from_shared_6b(Eurydice_borrow_slice_u8 s, size_t r)
{
  return ((Eurydice_borrow_slice_u8){ s.ptr + r, s.meta - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1120size_t
*/
typedef struct Eurydice_arr_480_s { uint8_t data[1120U]; } Eurydice_arr_480;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1120
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_74(const Eurydice_arr_480 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1120U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1088
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_42(const Eurydice_arr_2c *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1088U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_8c2(Eurydice_arr_480 *a, size_t r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r, (size_t)1120U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3611(Eurydice_arr_480 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_8c1(Eurydice_arr_060 *a, size_t r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r, (size_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_3610(Eurydice_arr_060 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_8c0(const Eurydice_arr_2c *a, size_t r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r, (size_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_364(const Eurydice_arr_2c *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2400
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_ec(const Eurydice_arr_ea *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)2400U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 16
*/
static inline Eurydice_borrow_slice_i16
Eurydice_array_to_subslice_shared_85(const Eurydice_arr_e2 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_i16){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
static inline Eurydice_borrow_slice_i16
Eurydice_slice_subslice_shared_76(Eurydice_borrow_slice_i16 s, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_i16){ s.ptr + r.start, r.end - r.start });
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_e2, core_array_TryFromSliceError

*/
typedef struct Result_f4_s
{
  Result_80_tags tag;
  union {
    Eurydice_arr_e2 case_Ok;
    TryFromSliceError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_f4_s)
}
Result_f4;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr int16_t[[$16size_t]], core_array_TryFromSliceError

*/
static inline Eurydice_arr_e2 unwrap_26_0e(Result_f4 self)
{
  if (self.tag == Ok)
  {
    return self.val.case_Ok;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $128size_t
*/
typedef struct Eurydice_arr_49_s { int16_t data[128U]; } Eurydice_arr_49;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_363(const Eurydice_arr_6d *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_369(Eurydice_arr_6d *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 16
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_46(Eurydice_arr_88 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)16U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_362(const Eurydice_arr_88 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_368(Eurydice_arr_88 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $19size_t
*/
typedef struct Eurydice_arr_91_s { uint8_t data[19U]; } Eurydice_arr_91;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_361(const Eurydice_arr_91 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_367(Eurydice_arr_91 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types int32_t, size_t

*/
typedef struct Eurydice_dst_ref_mut_fc_s
{
  int32_t *ptr;
  size_t meta;
}
Eurydice_dst_ref_mut_fc;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
static inline Eurydice_dst_ref_mut_fc
Eurydice_slice_subslice_mut_46(Eurydice_dst_ref_mut_fc s, core_ops_range_Range_08 r)
{
  return ((Eurydice_dst_ref_mut_fc){ s.ptr + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 16
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_46(const Eurydice_arr_88 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)16U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_88
with const generics
- $16size_t
*/
typedef struct Eurydice_arr_0e_s { Eurydice_arr_88 data[16U]; } Eurydice_arr_0e;

/**
A monomorphic instance of Eurydice.array_to_subslice_to_mut
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_to_mut_6e(Eurydice_arr_600 *a, size_t r)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = r;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $3309size_t
*/
typedef struct Eurydice_arr_96_s { uint8_t data[3309U]; } Eurydice_arr_96;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 3309
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_ee0(const Eurydice_arr_96 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)3309U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1952size_t
*/
typedef struct Eurydice_arr_4a_s { uint8_t data[1952U]; } Eurydice_arr_4a;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1952
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_5b(const Eurydice_arr_4a *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1952U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4032size_t
*/
typedef struct Eurydice_arr_d10_s { uint8_t data[4032U]; } Eurydice_arr_d10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4032
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_ef(const Eurydice_arr_d10 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)4032U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $256size_t
*/
typedef struct Eurydice_arr_c3_s { int32_t data[256U]; } Eurydice_arr_c3;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c3
with const generics
- $6size_t
*/
typedef struct Eurydice_arr_b5_s { Eurydice_arr_c3 data[6U]; } Eurydice_arr_b5;

#define None 0
#define Some 1

typedef uint8_t Option_cb_tags;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_b5

*/
typedef struct Option_cb_s
{
  Option_cb_tags tag;
  Eurydice_arr_b5 f0;
}
Option_cb;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $48size_t
*/
typedef struct Eurydice_arr_5f_s { uint8_t data[48U]; } Eurydice_arr_5f;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5f

*/
typedef struct Option_a6_s
{
  Option_cb_tags tag;
  Eurydice_arr_5f f0;
}
Option_a6;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 3309
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_ee0(Eurydice_arr_96 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)3309U;
  return lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_c3, size_t

*/
typedef struct Eurydice_dst_ref_shared_22_s
{
  const Eurydice_arr_c3 *ptr;
  size_t meta;
}
Eurydice_dst_ref_shared_22;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
static inline Eurydice_dst_ref_shared_22
Eurydice_array_to_slice_shared_6d(const Eurydice_arr_b5 *a)
{
  Eurydice_dst_ref_shared_22 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)6U;
  return lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_c3, size_t

*/
typedef struct Eurydice_dst_ref_mut_22_s
{
  Eurydice_arr_c3 *ptr;
  size_t meta;
}
Eurydice_dst_ref_mut_22;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
static inline Eurydice_dst_ref_mut_22 Eurydice_array_to_slice_mut_6d(Eurydice_arr_b5 *a)
{
  Eurydice_dst_ref_mut_22 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)6U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 256
*/
static inline Eurydice_dst_ref_mut_fc
Eurydice_array_to_subslice_mut_7f(Eurydice_arr_c3 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_dst_ref_mut_fc){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 48
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_95(const Eurydice_arr_5f *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)48U;
  return lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types int32_t, size_t

*/
typedef struct Eurydice_dst_ref_shared_fc_s
{
  const int32_t *ptr;
  size_t meta;
}
Eurydice_dst_ref_shared_fc;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 256
*/
static inline Eurydice_dst_ref_shared_fc
Eurydice_array_to_slice_shared_200(const Eurydice_arr_c3 *a)
{
  Eurydice_dst_ref_shared_fc lit;
  lit.ptr = a->data;
  lit.meta = (size_t)256U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $136size_t
*/
typedef struct Eurydice_arr_3d_s { uint8_t data[136U]; } Eurydice_arr_3d;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_8c(const Eurydice_arr_3d *a, size_t r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r, (size_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_360(const Eurydice_arr_3d *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $768size_t
*/
typedef struct Eurydice_arr_56_s { uint8_t data[768U]; } Eurydice_arr_56;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 768
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_ee(const Eurydice_arr_56 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)768U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 768
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_ee(Eurydice_arr_56 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)768U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $640size_t
*/
typedef struct Eurydice_arr_c30_s { uint8_t data[640U]; } Eurydice_arr_c30;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 640
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_7d0(const Eurydice_arr_c30 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)640U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 640
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_7d(Eurydice_arr_c30 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)640U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $576size_t
*/
typedef struct Eurydice_arr_5f0_s { uint8_t data[576U]; } Eurydice_arr_5f0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 576
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_fa(const Eurydice_arr_5f0 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)576U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 576
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_fa(Eurydice_arr_5f0 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)576U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $11size_t
*/
typedef struct Eurydice_arr_cb_s { uint8_t data[11U]; } Eurydice_arr_cb;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 11
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_da(const Eurydice_arr_cb *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)11U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1size_t
*/
typedef struct Eurydice_arr_f10_s { uint8_t data[1U]; } Eurydice_arr_f10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_07(const Eurydice_arr_f10 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1952
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_5b(Eurydice_arr_4a *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)1952U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4032
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_ef(Eurydice_arr_d10 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)4032U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 64
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_d8(const Eurydice_arr_060 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)64U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $263size_t
*/
typedef struct Eurydice_arr_13_s { int32_t data[263U]; } Eurydice_arr_13;

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_13, size_t

*/
typedef struct Eurydice_dst_ref_mut_4c_s
{
  Eurydice_arr_13 *ptr;
  size_t meta;
}
Eurydice_dst_ref_mut_4c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_13
with const generics
- $4size_t
*/
typedef struct Eurydice_arr_380_s { Eurydice_arr_13 data[4U]; } Eurydice_arr_380;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$263size_t]]
with const generics
- N= 4
*/
static inline Eurydice_dst_ref_mut_4c Eurydice_array_to_slice_mut_f6(Eurydice_arr_380 *a)
{
  Eurydice_dst_ref_mut_4c lit;
  lit.ptr = a->data;
  lit.meta = (size_t)4U;
  return lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_13, size_t

*/
typedef struct Eurydice_dst_ref_shared_4c_s
{
  const Eurydice_arr_13 *ptr;
  size_t meta;
}
Eurydice_dst_ref_shared_4c;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $840size_t
*/
typedef struct Eurydice_arr_12_s { uint8_t data[840U]; } Eurydice_arr_12;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 840
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_a8(const Eurydice_arr_12 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)840U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 34
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_8d(const Eurydice_arr_48 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)34U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 263
*/
static inline Eurydice_dst_ref_shared_fc
Eurydice_array_to_slice_shared_20(const Eurydice_arr_13 *a)
{
  Eurydice_dst_ref_shared_fc lit;
  lit.ptr = a->data;
  lit.meta = (size_t)263U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types int32_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 263
*/
static inline Eurydice_dst_ref_mut_fc
Eurydice_array_to_subslice_from_mut_96(Eurydice_arr_13 *a, size_t r)
{
  return ((Eurydice_dst_ref_mut_fc){ a->data + r, (size_t)263U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $66size_t
*/
typedef struct Eurydice_arr_a2_s { uint8_t data[66U]; } Eurydice_arr_a2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 66
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_39(const Eurydice_arr_a2 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)66U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 128
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_18(const Eurydice_arr_d1 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)128U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 128
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_18(Eurydice_arr_d1 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)128U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_26(const Eurydice_array_u8x2 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)2U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 32
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_6e(const Eurydice_arr_600 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)32U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $8size_t
*/
typedef struct Eurydice_arr_d4_s { int32_t data[8U]; } Eurydice_arr_d4;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 8
*/
static inline Eurydice_dst_ref_shared_fc
Eurydice_array_to_subslice_shared_7f(const Eurydice_arr_d4 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_dst_ref_shared_fc){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 8
*/
static inline Eurydice_dst_ref_shared_fc
Eurydice_array_to_slice_shared_a7(const Eurydice_arr_d4 *a)
{
  Eurydice_dst_ref_shared_fc lit;
  lit.ptr = a->data;
  lit.meta = (size_t)8U;
  return lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
static inline Eurydice_dst_ref_shared_fc
Eurydice_slice_subslice_shared_46(Eurydice_dst_ref_shared_fc s, core_ops_range_Range_08 r)
{
  return ((Eurydice_dst_ref_shared_fc){ s.ptr + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types int32_t
with const generics
- N= 8
*/
static inline Eurydice_dst_ref_mut_fc Eurydice_array_to_slice_mut_a7(Eurydice_arr_d4 *a)
{
  Eurydice_dst_ref_mut_fc lit;
  lit.ptr = a->data;
  lit.meta = (size_t)8U;
  return lit;
}

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_cb

*/
typedef struct Option_b5_s
{
  Option_cb_tags tag;
  Eurydice_arr_cb f0;
}
Option_b5;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 34
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_366(Eurydice_arr_48 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 66
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_365(Eurydice_arr_a2 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 168
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_7b(Eurydice_arr_27 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)168U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 840
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_a8(Eurydice_arr_12 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)840U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 136
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_d4(Eurydice_arr_3d *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)136U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_36(const Eurydice_arr_600 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_3d
with const generics
- $4size_t
*/
typedef struct Eurydice_arr_1a_s { Eurydice_arr_3d data[4U]; } Eurydice_arr_1a;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_27
with const generics
- $4size_t
*/
typedef struct Eurydice_arr_b3_s { Eurydice_arr_27 data[4U]; } Eurydice_arr_b3;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $4size_t
*/
typedef struct Eurydice_arr_cd_s { Eurydice_borrow_slice_u8 data[4U]; } Eurydice_arr_cd;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_364(Eurydice_arr_600 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_8c0(Eurydice_arr_27 *a, size_t r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r, (size_t)168U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_27
with const generics
- $1size_t
*/
typedef struct Eurydice_arr_3a_s { Eurydice_arr_27 data[1U]; } Eurydice_arr_3a;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 64
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_d8(Eurydice_arr_060 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)64U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 48
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_95(Eurydice_arr_5f *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)48U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 32
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_6e(Eurydice_arr_600 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)32U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $28size_t
*/
typedef struct Eurydice_arr_f1_s { uint8_t data[28U]; } Eurydice_arr_f1;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 28
*/
static inline Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_c0(Eurydice_arr_f1 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)28U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $104size_t
*/
typedef struct Eurydice_arr_18_s { uint8_t data[104U]; } Eurydice_arr_18;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 104
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_9c(const Eurydice_arr_18 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)104U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 104
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_363(Eurydice_arr_18 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $144size_t
*/
typedef struct Eurydice_arr_a8_s { uint8_t data[144U]; } Eurydice_arr_a8;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 144
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_d1(const Eurydice_arr_a8 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)144U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 144
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_362(Eurydice_arr_a8 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $72size_t
*/
typedef struct Eurydice_arr_a0_s { uint8_t data[72U]; } Eurydice_arr_a0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 72
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_7d(const Eurydice_arr_a0 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)72U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 72
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_361(Eurydice_arr_a0 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.slice_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t

*/
static inline Eurydice_borrow_slice_u8
Eurydice_slice_subslice_to_shared_c6(Eurydice_borrow_slice_u8 s, size_t r)
{
  return ((Eurydice_borrow_slice_u8){ s.ptr, r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_8c(Eurydice_arr_3d *a, size_t r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r, (size_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 8
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_to_shared_6e(const Eurydice_array_u8x8 *a, size_t r)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = r;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 8
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_41(const Eurydice_array_u8x8 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)8U;
  return lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_slice_subslice_mut_7e(Eurydice_mut_borrow_slice_u8 s, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ s.ptr + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 136
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_d4(const Eurydice_arr_3d *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)136U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_360(Eurydice_arr_3d *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $5size_t
*/
typedef struct Eurydice_arr_a5_s { uint64_t data[5U]; } Eurydice_arr_a5;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $1size_t
*/
typedef struct Eurydice_arr_06_s { Eurydice_borrow_slice_u8 data[1U]; } Eurydice_arr_06;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 168
*/
static inline Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_7b(const Eurydice_arr_27 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)168U;
  return lit;
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_array_u8x8, core_array_TryFromSliceError

*/
typedef struct Result_8e_s
{
  Result_80_tags tag;
  union {
    Eurydice_array_u8x8 case_Ok;
    TryFromSliceError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_8e_s)
}
Result_8e;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$8size_t]], core_array_TryFromSliceError

*/
static inline Eurydice_array_u8x8 unwrap_26_ab(Result_8e self)
{
  if (self.tag == Ok)
  {
    return self.val.case_Ok;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
static inline Eurydice_borrow_slice_u8
Eurydice_slice_subslice_shared_7e(Eurydice_borrow_slice_u8 s, core_ops_range_Range_08 r)
{
  return ((Eurydice_borrow_slice_u8){ s.ptr + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
static inline Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_36(Eurydice_arr_27 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_mut_borrow_slice_u8){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $24size_t
*/
typedef struct Eurydice_arr_a7_s { uint64_t data[24U]; } Eurydice_arr_a7;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_3d
with const generics
- $1size_t
*/
typedef struct Eurydice_arr_3e_s { Eurydice_arr_3d data[1U]; } Eurydice_arr_3e;

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $25size_t
*/
typedef struct Eurydice_arr_26_s { uint64_t data[25U]; } Eurydice_arr_26;


#define libcrux_core_H_DEFINED
#endif /* libcrux_core_H */

/* from libcrux/combined_extraction/generated/libcrux_sha3_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_sha3_portable_H
#define libcrux_sha3_portable_H





/**
A monomorphic instance of libcrux_sha3.generic_keccak.KeccakState
with types uint64_t
with const generics
- $1size_t
*/
typedef Eurydice_arr_26 libcrux_sha3_generic_keccak_KeccakState_17;

typedef libcrux_sha3_generic_keccak_KeccakState_17 libcrux_sha3_portable_KeccakState;

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $136size_t
*/
typedef struct libcrux_sha3_generic_keccak_xof_KeccakXofState_e2_s
{
  Eurydice_arr_26 inner;
  Eurydice_arr_3e buf;
  size_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_e2;

typedef libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
libcrux_sha3_portable_incremental_Shake256Xof;

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_zero_d2(void)
{
  return 0ULL;
}

static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__veor5q_u64(
  uint64_t a,
  uint64_t b,
  uint64_t c,
  uint64_t d,
  uint64_t e
)
{
  return (((a ^ b) ^ c) ^ d) ^ e;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor5_d2(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
  return libcrux_sha3_simd_portable__veor5q_u64(a, b, c, d, e);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 1
- RIGHT= 63
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_76(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)1);
}

static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__vrax1q_u64(uint64_t a, uint64_t b)
{
  return a ^ libcrux_sha3_simd_portable_rotate_left_76(b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vrax1q_u64(a, b);
}

static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vbcaxq_u64(uint64_t a, uint64_t b, uint64_t c)
{
  return a ^ (b & ~c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_and_not_xor_d2(uint64_t a, uint64_t b, uint64_t c)
{
  return libcrux_sha3_simd_portable__vbcaxq_u64(a, b, c);
}

static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__veorq_n_u64(uint64_t a, uint64_t c)
{
  return a ^ c;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_constant_d2(uint64_t a, uint64_t c)
{
  return libcrux_sha3_simd_portable__veorq_n_u64(a, c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_xor_d2(uint64_t a, uint64_t b)
{
  return a ^ b;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.new_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE Eurydice_arr_26 libcrux_sha3_generic_keccak_new_80_04(void)
{
  Eurydice_arr_26 lit;
  uint64_t repeat_expression[25U];
  for (size_t i = (size_t)0U; i < (size_t)25U; i++)
  {
    repeat_expression[i] = libcrux_sha3_simd_portable_zero_d2();
  }
  memcpy(lit.data, repeat_expression, (size_t)25U * sizeof (uint64_t));
  return lit;
}

/**
 Create a new SHAKE-128 state object.
*/
static KRML_MUSTINLINE Eurydice_arr_26 libcrux_sha3_portable_incremental_shake128_init(void)
{
  return libcrux_sha3_generic_keccak_new_80_04();
}

#define LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS (((Eurydice_arr_a7){ { 1ULL, 32898ULL, 9223372036854808714ULL, 9223372039002292224ULL, 32907ULL, 2147483649ULL, 9223372039002292353ULL, 9223372036854808585ULL, 138ULL, 136ULL, 2147516425ULL, 2147483658ULL, 2147516555ULL, 9223372036854775947ULL, 9223372036854808713ULL, 9223372036854808579ULL, 9223372036854808578ULL, 9223372036854775936ULL, 32778ULL, 9223372039002259466ULL, 9223372039002292353ULL, 9223372036854808704ULL, 2147483649ULL, 9223372039002292232ULL } }))

typedef struct size_t_x2_s
{
  size_t fst;
  size_t snd;
}
size_t_x2;

/**
A monomorphic instance of libcrux_sha3.traits.get_ij
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE const
uint64_t
*libcrux_sha3_traits_get_ij_04(const Eurydice_arr_26 *arr, size_t i, size_t j)
{
  return &arr->data[(size_t)5U * j + i];
}

/**
A monomorphic instance of libcrux_sha3.traits.set_ij
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_traits_set_ij_04(Eurydice_arr_26 *arr, size_t i, size_t j, uint64_t value)
{
  arr->data[(size_t)5U * j + i] = value;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_block_3a(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start
)
{
  Eurydice_arr_26 state_flat = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)168U / (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t offset = start + (size_t)8U * i0;
    Eurydice_array_u8x8 arr;
    memcpy(arr.data,
      Eurydice_slice_subslice_shared_7e(blocks,
        ((core_ops_range_Range_08){ offset, offset + (size_t)8U })).ptr,
      (size_t)8U * sizeof (uint8_t));
    Eurydice_array_u8x8 uu____0 = unwrap_26_ab((Result_8e){ .tag = Ok, .val = { .case_Ok = arr } });
    state_flat.data[i0] = core_num__u64__from_le_bytes(uu____0);
  }
  for (size_t i = (size_t)0U; i < (size_t)168U / (size_t)8U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_traits_set_ij_04(state,
      i0 / (size_t)5U,
      i0 % (size_t)5U,
      libcrux_sha3_traits_get_ij_04(state, i0 / (size_t)5U, i0 % (size_t)5U)[0U] ^
        state_flat.data[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 168
- DELIMITER= 31
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_last_c6(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start,
  size_t len
)
{
  Eurydice_arr_27 buffer = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_36(&buffer,
      ((core_ops_range_Range_08){ (size_t)0U, len })),
    Eurydice_slice_subslice_shared_7e(blocks, ((core_ops_range_Range_08){ start, start + len })),
    uint8_t);
  buffer.data[len] = 31U;
  size_t uu____0 = (size_t)168U - (size_t)1U;
  buffer.data[uu____0] = (uint32_t)buffer.data[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_3a(state,
    Eurydice_array_to_slice_shared_7b(&buffer),
    (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 168
- DELIMITER= 31
*/
static inline void
libcrux_sha3_simd_portable_load_last_a1_c6(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_c6(self, input->data[0U], start, len);
}

/**
This function found in impl {core::ops::index::Index<(usize, usize), T> for libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.index_c2
with types uint64_t
with const generics
- N= 1
*/
static inline const
uint64_t
*libcrux_sha3_generic_keccak_index_c2_04(const Eurydice_arr_26 *self, size_t_x2 index)
{
  return libcrux_sha3_traits_get_ij_04(self, index.fst, index.snd);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.theta_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE Eurydice_arr_a5
libcrux_sha3_generic_keccak_theta_80_04(Eurydice_arr_26 *self)
{
  Eurydice_arr_a5
  c =
    {
      {
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
            ((size_t_x2){ (size_t)0U, (size_t)0U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)1U, (size_t)0U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)2U, (size_t)0U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)3U, (size_t)0U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)4U, (size_t)0U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
            ((size_t_x2){ (size_t)0U, (size_t)1U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)1U, (size_t)1U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)2U, (size_t)1U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)3U, (size_t)1U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)4U, (size_t)1U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
            ((size_t_x2){ (size_t)0U, (size_t)2U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)1U, (size_t)2U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)2U, (size_t)2U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)3U, (size_t)2U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)4U, (size_t)2U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
            ((size_t_x2){ (size_t)0U, (size_t)3U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)1U, (size_t)3U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)2U, (size_t)3U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)3U, (size_t)3U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)4U, (size_t)3U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
            ((size_t_x2){ (size_t)0U, (size_t)4U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)1U, (size_t)4U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)2U, (size_t)4U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)3U, (size_t)4U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(self, ((size_t_x2){ (size_t)4U, (size_t)4U }))[0U])
      }
    };
  return
    (
      (Eurydice_arr_a5){
        {
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.data[((size_t)0U + (size_t)4U) %
              (size_t)5U],
            c.data[((size_t)0U + (size_t)1U) % (size_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.data[((size_t)1U + (size_t)4U) %
              (size_t)5U],
            c.data[((size_t)1U + (size_t)1U) % (size_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.data[((size_t)2U + (size_t)4U) %
              (size_t)5U],
            c.data[((size_t)2U + (size_t)1U) % (size_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.data[((size_t)3U + (size_t)4U) %
              (size_t)5U],
            c.data[((size_t)3U + (size_t)1U) % (size_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.data[((size_t)4U + (size_t)4U) %
              (size_t)5U],
            c.data[((size_t)4U + (size_t)1U) % (size_t)5U])
        }
      }
    );
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.set_80
with types uint64_t
with const generics
- N= 1
*/
static inline void
libcrux_sha3_generic_keccak_set_80_04(Eurydice_arr_26 *self, size_t i, size_t j, uint64_t v)
{
  libcrux_sha3_traits_set_ij_04(self, i, j, v);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 36
- RIGHT= 28
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_02(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)36);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 36
- RIGHT= 28
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_02(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_02(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 36
- RIGHT= 28
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_02(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_02(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 3
- RIGHT= 61
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_ac(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)3);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 3
- RIGHT= 61
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ac(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_ac(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 3
- RIGHT= 61
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_ac(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 41
- RIGHT= 23
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_020(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)41);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 41
- RIGHT= 23
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_020(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_020(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 41
- RIGHT= 23
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_020(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_020(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 18
- RIGHT= 46
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_a9(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)18);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 18
- RIGHT= 46
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_a9(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_a9(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 18
- RIGHT= 46
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_a9(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_0_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_rho_0_80_04(Eurydice_arr_26 *self, Eurydice_arr_a5 t)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)0U,
    libcrux_sha3_simd_portable_xor_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)0U, (size_t)0U }))[0U],
      t.data[0U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_02(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)1U, (size_t)0U }))[0U],
      t.data[0U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)2U, (size_t)0U }))[0U],
      t.data[0U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_020(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)3U, (size_t)0U }))[0U],
      t.data[0U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)4U, (size_t)0U }))[0U],
      t.data[0U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 1
- RIGHT= 63
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_76(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_76(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 1
- RIGHT= 63
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_76(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_76(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 44
- RIGHT= 20
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_58(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)44);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 44
- RIGHT= 20
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_58(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_58(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 44
- RIGHT= 20
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_58(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_58(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 10
- RIGHT= 54
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_e0(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)10);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 10
- RIGHT= 54
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_e0(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_e0(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 10
- RIGHT= 54
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_e0(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 45
- RIGHT= 19
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_63(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)45);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 45
- RIGHT= 19
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_63(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_63(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 45
- RIGHT= 19
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_63(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_63(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 2
- RIGHT= 62
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_6a(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)2);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 2
- RIGHT= 62
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6a(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_6a(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 2
- RIGHT= 62
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_6a(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_1_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_rho_1_80_04(Eurydice_arr_26 *self, Eurydice_arr_a5 t)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_76(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)0U, (size_t)1U }))[0U],
      t.data[1U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_58(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)1U, (size_t)1U }))[0U],
      t.data[1U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)2U, (size_t)1U }))[0U],
      t.data[1U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_63(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)3U, (size_t)1U }))[0U],
      t.data[1U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)4U, (size_t)1U }))[0U],
      t.data[1U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 62
- RIGHT= 2
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_ab(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)62);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 62
- RIGHT= 2
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ab(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_ab(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 62
- RIGHT= 2
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_ab(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 6
- RIGHT= 58
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_5b(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)6);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 6
- RIGHT= 58
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_5b(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_5b(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 6
- RIGHT= 58
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_5b(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 43
- RIGHT= 21
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_6f(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)43);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 43
- RIGHT= 21
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6f(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_6f(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 43
- RIGHT= 21
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_6f(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 15
- RIGHT= 49
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_62(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)15);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 15
- RIGHT= 49
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_62(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_62(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 15
- RIGHT= 49
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_62(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_62(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 61
- RIGHT= 3
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_23(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)61);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 61
- RIGHT= 3
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_23(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_23(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 61
- RIGHT= 3
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_23(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_23(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_2_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_rho_2_80_04(Eurydice_arr_26 *self, Eurydice_arr_a5 t)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)0U, (size_t)2U }))[0U],
      t.data[2U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)1U, (size_t)2U }))[0U],
      t.data[2U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)2U, (size_t)2U }))[0U],
      t.data[2U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_62(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)3U, (size_t)2U }))[0U],
      t.data[2U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_23(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)4U, (size_t)2U }))[0U],
      t.data[2U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 28
- RIGHT= 36
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_37(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)28);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 28
- RIGHT= 36
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_37(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_37(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 28
- RIGHT= 36
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_37(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_37(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 55
- RIGHT= 9
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_bb(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)55);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 55
- RIGHT= 9
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_bb(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_bb(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 55
- RIGHT= 9
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_bb(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 25
- RIGHT= 39
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_b9(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)25);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 25
- RIGHT= 39
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_b9(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_b9(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 25
- RIGHT= 39
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_b9(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 21
- RIGHT= 43
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_54(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)21);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 21
- RIGHT= 43
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_54(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_54(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 21
- RIGHT= 43
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_54(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_54(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 56
- RIGHT= 8
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_4c(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)56);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 56
- RIGHT= 8
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_4c(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_4c(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 56
- RIGHT= 8
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_4c(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_3_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_rho_3_80_04(Eurydice_arr_26 *self, Eurydice_arr_a5 t)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_37(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)0U, (size_t)3U }))[0U],
      t.data[3U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)1U, (size_t)3U }))[0U],
      t.data[3U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)2U, (size_t)3U }))[0U],
      t.data[3U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_54(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)3U, (size_t)3U }))[0U],
      t.data[3U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)4U, (size_t)3U }))[0U],
      t.data[3U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 27
- RIGHT= 37
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_ce(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)27);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 27
- RIGHT= 37
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ce(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_ce(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 27
- RIGHT= 37
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_ce(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 20
- RIGHT= 44
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_77(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)20);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 20
- RIGHT= 44
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_77(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_77(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 20
- RIGHT= 44
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_77(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_77(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 39
- RIGHT= 25
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_25(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)39);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 39
- RIGHT= 25
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_25(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_25(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 39
- RIGHT= 25
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_25(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_25(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 8
- RIGHT= 56
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_af(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)8);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 8
- RIGHT= 56
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_af(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_af(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 8
- RIGHT= 56
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_af(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_af(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 14
- RIGHT= 50
*/
static KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_left_fd(uint64_t x)
{
  return core_num__u64__rotate_left(x, (uint32_t)(int32_t)14);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 14
- RIGHT= 50
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_fd(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable_rotate_left_fd(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 14
- RIGHT= 50
*/
static KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(uint64_t a, uint64_t b)
{
  return libcrux_sha3_simd_portable__vxarq_u64_fd(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_4_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_rho_4_80_04(Eurydice_arr_26 *self, Eurydice_arr_a5 t)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)0U, (size_t)4U }))[0U],
      t.data[4U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_77(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)1U, (size_t)4U }))[0U],
      t.data[4U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_25(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)2U, (size_t)4U }))[0U],
      t.data[4U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_af(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)3U, (size_t)4U }))[0U],
      t.data[4U]));
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)4U, (size_t)4U }))[0U],
      t.data[4U]));
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_rho_80_04(Eurydice_arr_26 *self, Eurydice_arr_a5 t)
{
  libcrux_sha3_generic_keccak_rho_0_80_04(self, t);
  libcrux_sha3_generic_keccak_rho_1_80_04(self, t);
  libcrux_sha3_generic_keccak_rho_2_80_04(self, t);
  libcrux_sha3_generic_keccak_rho_3_80_04(self, t);
  libcrux_sha3_generic_keccak_rho_4_80_04(self, t);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_0_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_pi_0_80_04(Eurydice_arr_26 *self, Eurydice_arr_26 old)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)0U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)0U, (size_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)0U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)0U, (size_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)0U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)0U, (size_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)0U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)0U, (size_t)2U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_1_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_pi_1_80_04(Eurydice_arr_26 *self, Eurydice_arr_26 old)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)1U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)1U, (size_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)1U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)1U, (size_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)1U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)1U, (size_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)1U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)1U, (size_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)1U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)1U, (size_t)3U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_2_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_pi_2_80_04(Eurydice_arr_26 *self, Eurydice_arr_26 old)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)2U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)2U, (size_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)2U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)2U, (size_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)2U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)2U, (size_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)2U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)2U, (size_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)2U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)2U, (size_t)4U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_3_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_pi_3_80_04(Eurydice_arr_26 *self, Eurydice_arr_26 old)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)3U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)3U, (size_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)3U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)3U, (size_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)3U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)3U, (size_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)3U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)3U, (size_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)3U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)3U, (size_t)0U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_4_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_pi_4_80_04(Eurydice_arr_26 *self, Eurydice_arr_26 old)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)4U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)4U, (size_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)1U,
    (size_t)4U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)4U, (size_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)2U,
    (size_t)4U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)4U, (size_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)3U,
    (size_t)4U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)4U, (size_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)4U,
    (size_t)4U,
    libcrux_sha3_generic_keccak_index_c2_04(&old, ((size_t_x2){ (size_t)4U, (size_t)1U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void libcrux_sha3_generic_keccak_pi_80_04(Eurydice_arr_26 *self)
{
  Eurydice_arr_26 old = self[0U];
  libcrux_sha3_generic_keccak_pi_0_80_04(self, old);
  libcrux_sha3_generic_keccak_pi_1_80_04(self, old);
  libcrux_sha3_generic_keccak_pi_2_80_04(self, old);
  libcrux_sha3_generic_keccak_pi_3_80_04(self, old);
  libcrux_sha3_generic_keccak_pi_4_80_04(self, old);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.chi_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void libcrux_sha3_generic_keccak_chi_80_04(Eurydice_arr_26 *self)
{
  Eurydice_arr_26 old = self[0U];
  for (size_t i0 = (size_t)0U; i0 < (size_t)5U; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)5U; i++)
    {
      size_t j = i;
      libcrux_sha3_generic_keccak_set_80_04(self,
        i1,
        j,
        libcrux_sha3_simd_portable_and_not_xor_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
            ((size_t_x2){ i1, j }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(&old,
            ((size_t_x2){ i1, (j + (size_t)2U) % (size_t)5U }))[0U],
          libcrux_sha3_generic_keccak_index_c2_04(&old,
            ((size_t_x2){ i1, (j + (size_t)1U) % (size_t)5U }))[0U]));
    }
  }
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.iota_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_iota_80_04(Eurydice_arr_26 *self, size_t i)
{
  libcrux_sha3_generic_keccak_set_80_04(self,
    (size_t)0U,
    (size_t)0U,
    libcrux_sha3_simd_portable_xor_constant_d2(libcrux_sha3_generic_keccak_index_c2_04(self,
        ((size_t_x2){ (size_t)0U, (size_t)0U }))[0U],
      LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS.data[i]));
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.keccakf1600_80
with types uint64_t
with const generics
- N= 1
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_keccakf1600_80_04(Eurydice_arr_26 *self)
{
  for (size_t i = (size_t)0U; i < (size_t)24U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_a5 t = libcrux_sha3_generic_keccak_theta_80_04(self);
    libcrux_sha3_generic_keccak_rho_80_04(self, t);
    libcrux_sha3_generic_keccak_pi_80_04(self);
    libcrux_sha3_generic_keccak_chi_80_04(self);
    libcrux_sha3_generic_keccak_iota_80_04(self, i0);
  }
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 168
- DELIM= 31
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_final_80_9e(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_a1_c6(self, input, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
 Absorb
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake128_absorb_final(
  Eurydice_arr_26 *s,
  Eurydice_borrow_slice_u8 data0
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { data0 } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e(s, &lvalue, (size_t)0U, data0.meta);
}

/**
 Create a new SHAKE-256 state object.
*/
static KRML_MUSTINLINE Eurydice_arr_26 libcrux_sha3_portable_incremental_shake256_init(void)
{
  return libcrux_sha3_generic_keccak_new_80_04();
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_block_5b(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start
)
{
  Eurydice_arr_26 state_flat = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)136U / (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t offset = start + (size_t)8U * i0;
    Eurydice_array_u8x8 arr;
    memcpy(arr.data,
      Eurydice_slice_subslice_shared_7e(blocks,
        ((core_ops_range_Range_08){ offset, offset + (size_t)8U })).ptr,
      (size_t)8U * sizeof (uint8_t));
    Eurydice_array_u8x8 uu____0 = unwrap_26_ab((Result_8e){ .tag = Ok, .val = { .case_Ok = arr } });
    state_flat.data[i0] = core_num__u64__from_le_bytes(uu____0);
  }
  for (size_t i = (size_t)0U; i < (size_t)136U / (size_t)8U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_traits_set_ij_04(state,
      i0 / (size_t)5U,
      i0 % (size_t)5U,
      libcrux_sha3_traits_get_ij_04(state, i0 / (size_t)5U, i0 % (size_t)5U)[0U] ^
        state_flat.data[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 31
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_last_ad(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start,
  size_t len
)
{
  Eurydice_arr_3d buffer = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_360(&buffer,
      ((core_ops_range_Range_08){ (size_t)0U, len })),
    Eurydice_slice_subslice_shared_7e(blocks, ((core_ops_range_Range_08){ start, start + len })),
    uint8_t);
  buffer.data[len] = 31U;
  size_t uu____0 = (size_t)136U - (size_t)1U;
  buffer.data[uu____0] = (uint32_t)buffer.data[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_5b(state,
    Eurydice_array_to_slice_shared_d4(&buffer),
    (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 136
- DELIMITER= 31
*/
static inline void
libcrux_sha3_simd_portable_load_last_a1_ad(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_ad(self, input->data[0U], start, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
- DELIM= 31
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_final_80_9e0(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_a1_ad(self, input, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
 Absorb some data for SHAKE-256 for the last time
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake256_absorb_final(
  Eurydice_arr_26 *s,
  Eurydice_borrow_slice_u8 data
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { data } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e0(s, &lvalue, (size_t)0U, data.meta);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 168
*/
static inline void
libcrux_sha3_simd_portable_load_block_a1_3a(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_3a(self, input->data[0U], start);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_block_80_c6(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_a1_3a(self, input, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_store_block_3a(
  const Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  size_t octets = len / (size_t)8U;
  for (size_t i = (size_t)0U; i < octets; i++)
  {
    size_t i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          i0 / (size_t)5U,
          i0 % (size_t)5U)[0U]);
    size_t out_pos = start + (size_t)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + (size_t)8U })),
      Eurydice_array_to_slice_shared_41(&bytes),
      uint8_t);
  }
  size_t remaining = len % (size_t)8U;
  if (remaining > (size_t)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          octets / (size_t)5U,
          octets % (size_t)5U)[0U]);
    size_t out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_6e(&bytes, remaining),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 168
*/
static inline void
libcrux_sha3_simd_portable_squeeze_9b_3a(
  const Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_store_block_3a(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 168
- DELIM= 31
*/
static inline void
libcrux_sha3_generic_keccak_portable_keccak1_c6(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_26 s = libcrux_sha3_generic_keccak_new_80_04();
  size_t input_len = input.meta;
  size_t input_blocks = input_len / (size_t)168U;
  size_t input_rem = input_len % (size_t)168U;
  for (size_t i = (size_t)0U; i < input_blocks; i++)
  {
    size_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_06 lvalue = { { input } };
    libcrux_sha3_generic_keccak_absorb_block_80_c6(&s, &lvalue, i0 * (size_t)168U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e(&s, &lvalue, input_len - input_rem, input_rem);
  size_t output_len = output.meta;
  size_t output_blocks = output_len / (size_t)168U;
  size_t output_rem = output_len % (size_t)168U;
  if (output_blocks == (size_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_3a(&s, output, (size_t)0U, output_len);
  }
  else
  {
    libcrux_sha3_simd_portable_squeeze_9b_3a(&s, output, (size_t)0U, (size_t)168U);
    for (size_t i = (size_t)1U; i < output_blocks; i++)
    {
      size_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_3a(&s, output, i0 * (size_t)168U, (size_t)168U);
    }
    if (output_rem != (size_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_3a(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE128 implementation.
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_shake128(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 data
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_c6(data, digest);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 136
*/
static inline void
libcrux_sha3_simd_portable_load_block_a1_5b(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_5b(self, input->data[0U], start);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_block_80_c60(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_a1_5b(self, input, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_store_block_5b(
  const Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  size_t octets = len / (size_t)8U;
  for (size_t i = (size_t)0U; i < octets; i++)
  {
    size_t i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          i0 / (size_t)5U,
          i0 % (size_t)5U)[0U]);
    size_t out_pos = start + (size_t)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + (size_t)8U })),
      Eurydice_array_to_slice_shared_41(&bytes),
      uint8_t);
  }
  size_t remaining = len % (size_t)8U;
  if (remaining > (size_t)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          octets / (size_t)5U,
          octets % (size_t)5U)[0U]);
    size_t out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_6e(&bytes, remaining),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 136
*/
static inline void
libcrux_sha3_simd_portable_squeeze_9b_5b(
  const Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_store_block_5b(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 31
*/
static inline void
libcrux_sha3_generic_keccak_portable_keccak1_ad(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_26 s = libcrux_sha3_generic_keccak_new_80_04();
  size_t input_len = input.meta;
  size_t input_blocks = input_len / (size_t)136U;
  size_t input_rem = input_len % (size_t)136U;
  for (size_t i = (size_t)0U; i < input_blocks; i++)
  {
    size_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_06 lvalue = { { input } };
    libcrux_sha3_generic_keccak_absorb_block_80_c60(&s, &lvalue, i0 * (size_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e0(&s, &lvalue, input_len - input_rem, input_rem);
  size_t output_len = output.meta;
  size_t output_blocks = output_len / (size_t)136U;
  size_t output_rem = output_len % (size_t)136U;
  if (output_blocks == (size_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, (size_t)0U, output_len);
  }
  else
  {
    libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, (size_t)0U, (size_t)136U);
    for (size_t i = (size_t)1U; i < output_blocks; i++)
    {
      size_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, i0 * (size_t)136U, (size_t)136U);
    }
    if (output_rem != (size_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE256 implementation.
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_shake256(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 data
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_ad(data, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_block_b4
with const generics
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_portable_squeeze_first_block_b4_5b(
  const Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_simd_portable_squeeze_9b_5b(self, out, (size_t)0U, (size_t)136U);
}

/**
 Squeeze the first SHAKE-256 block
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake256_squeeze_first_block(
  Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_first_block_b4_5b(&s[0U], out);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_five_blocks_b4
with const generics
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_portable_squeeze_first_five_blocks_b4_3a(
  Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)0U, (size_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)168U, (size_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)2U * (size_t)168U, (size_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)3U * (size_t)168U, (size_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)4U * (size_t)168U, (size_t)168U);
}

/**
 Squeeze five blocks
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(
  Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_first_five_blocks_b4_3a(s, out0);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_portable_squeeze_next_block_b4_3a(
  Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, start, (size_t)168U);
}

/**
 Squeeze another block
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake128_squeeze_next_block(
  Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_next_block_b4_3a(s, out0, (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_portable_squeeze_next_block_b4_5b(
  Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_5b(self, out, start, (size_t)136U);
}

/**
 Squeeze the next SHAKE-256 block
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake256_squeeze_next_block(
  Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_next_block_b4_5b(s, out, (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.fill_buffer_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static inline size_t
libcrux_sha3_generic_keccak_xof_fill_buffer_35_c6(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  const Eurydice_arr_06 *inputs
)
{
  size_t input_len = inputs->data->meta;
  size_t uu____0;
  if (self->buf_len != (size_t)0U)
  {
    if (input_len >= (size_t)136U - self->buf_len)
    {
      size_t consumed = (size_t)136U - self->buf_len;
      for (size_t i = (size_t)0U; i < (size_t)1U; i++)
      {
        size_t i0 = i;
        Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_8c(&self->buf.data[i0],
            self->buf_len),
          Eurydice_slice_subslice_to_shared_c6(inputs->data[i0], consumed),
          uint8_t);
      }
      self->buf_len = (size_t)136U;
      uu____0 = consumed;
    }
    else
    {
      uu____0 = (size_t)0U;
    }
  }
  else
  {
    uu____0 = (size_t)0U;
  }
  return uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $136size_t
*/
typedef const Eurydice_arr_3e *libcrux_sha3_generic_keccak_xof_buf_to_slices_closure_cc;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ (@Slice<u8>)> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_a7
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static inline Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_a7_5b(
  const Eurydice_arr_3e **_,
  size_t tupled_args
)
{
  size_t i = tupled_args;
  return
    core_array___Array_T__N___as_slice((size_t)136U,
      &_[0U]->data[i],
      uint8_t,
      Eurydice_borrow_slice_u8);
}

/**
This function found in impl {core::ops::function::FnOnce<(usize), &'_ (@Slice<u8>)> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_once_2d
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static inline Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_once_2d_5b(
  const Eurydice_arr_3e *_,
  size_t _0
)
{
  return libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_a7_5b(&_, _0);
}

/**
 Note: This function exists to work around a hax bug where `core::array::from_fn`
 is extracted with an incorrect explicit type parameter `#(usize -> t_Slice u8)`
 instead of using the typeclass-based implicit parameter `#v_F` from
 `Core_models.Array.from_fn`.
 See: https://github.com/cryspen/hax/issues/1920
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static KRML_MUSTINLINE Eurydice_arr_06
libcrux_sha3_generic_keccak_xof_buf_to_slices_5b(const Eurydice_arr_3e *buf)
{
  Eurydice_arr_06 arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)1U; i++)
  {
    arr_struct.data[i] = libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_a7_5b(&buf, i);
  }
  return arr_struct;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_full_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static inline size_t
libcrux_sha3_generic_keccak_xof_absorb_full_35_c6(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  const Eurydice_arr_06 *inputs
)
{
  size_t consumed = libcrux_sha3_generic_keccak_xof_fill_buffer_35_c6(self, inputs);
  if (self->buf_len == (size_t)136U)
  {
    Eurydice_arr_06 borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_5b(&self->buf);
    libcrux_sha3_simd_portable_load_block_a1_5b(&self->inner, &borrowed, (size_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
    self->buf_len = (size_t)0U;
  }
  size_t input_to_consume = inputs->data->meta - consumed;
  size_t num_blocks = input_to_consume / (size_t)136U;
  size_t remainder = input_to_consume % (size_t)136U;
  for (size_t i = (size_t)0U; i < num_blocks; i++)
  {
    size_t i0 = i;
    size_t start = i0 * (size_t)136U + consumed;
    libcrux_sha3_simd_portable_load_block_a1_5b(&self->inner, inputs, start);
    libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
  }
  return remainder;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_xof_absorb_35_c6(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  const Eurydice_arr_06 *inputs
)
{
  size_t remainder = libcrux_sha3_generic_keccak_xof_absorb_full_35_c6(self, inputs);
  if (remainder > (size_t)0U)
  {
    size_t input_len = inputs->data->meta;
    for (size_t i = (size_t)0U; i < (size_t)1U; i++)
    {
      size_t i0 = i;
      Eurydice_slice_copy(Eurydice_array_to_subslice_mut_360(&self->buf.data[i0],
          ((core_ops_range_Range_08){ self->buf_len, self->buf_len + remainder })),
        Eurydice_slice_subslice_shared_7e(inputs->data[i0],
          ((core_ops_range_Range_08){ input_len - remainder, input_len })),
        uint8_t);
    }
    self->buf_len = self->buf_len + remainder;
  }
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
static inline void
libcrux_sha3_portable_incremental_absorb_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_borrow_slice_u8 input
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_xof_absorb_35_c6(self, &lvalue);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_final_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
- DELIMITER= 31
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_xof_absorb_final_35_9e(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  const Eurydice_arr_06 *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_c6(self, inputs);
  Eurydice_arr_06 borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_5b(&self->buf);
  libcrux_sha3_simd_portable_load_last_a1_ad(&self->inner, &borrowed, (size_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
static inline void
libcrux_sha3_portable_incremental_absorb_final_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_borrow_slice_u8 input
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_xof_absorb_final_35_9e(self, &lvalue);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.zero_block_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static inline Eurydice_arr_3d libcrux_sha3_generic_keccak_xof_zero_block_35_c6(void)
{
  return ((Eurydice_arr_3d){ { 0U } });
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.new_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
static inline libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
libcrux_sha3_generic_keccak_xof_new_35_c6(void)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_04();
  Eurydice_arr_3d repeat_expression[1U];
  for (size_t i = (size_t)0U; i < (size_t)1U; i++)
  {
    repeat_expression[i] = libcrux_sha3_generic_keccak_xof_zero_block_35_c6();
  }
  memcpy(lit.buf.data, repeat_expression, (size_t)1U * sizeof (Eurydice_arr_3d));
  lit.buf_len = (size_t)0U;
  lit.sponge = false;
  return lit;
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
static inline libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
libcrux_sha3_portable_incremental_new_42(void)
{
  return libcrux_sha3_generic_keccak_xof_new_35_c6();
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, 1usize, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.squeeze_85
with types uint64_t
with const generics
- RATE= 136
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_xof_squeeze_85_c7(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  size_t out_len = out.meta;
  if (!(out_len == (size_t)0U))
  {
    if (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
    }
    if (out_len > (size_t)0U)
    {
      size_t blocks = out_len / (size_t)136U;
      size_t last = out_len - out_len % (size_t)136U;
      if (blocks == (size_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_5b(&self->inner, out, (size_t)0U, out_len);
      }
      else
      {
        libcrux_sha3_simd_portable_squeeze_9b_5b(&self->inner, out, (size_t)0U, (size_t)136U);
        for (size_t i = (size_t)1U; i < blocks; i++)
        {
          size_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_5b(&self->inner,
            out,
            i0 * (size_t)136U,
            (size_t)136U);
        }
        if (last < out_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_5b(&self->inner, out, last, out_len - last);
        }
      }
    }
    self->sponge = true;
  }
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
static inline void
libcrux_sha3_portable_incremental_squeeze_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_c7(self, out);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 72
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_block_f8(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start
)
{
  Eurydice_arr_26 state_flat = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)72U / (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t offset = start + (size_t)8U * i0;
    Eurydice_array_u8x8 arr;
    memcpy(arr.data,
      Eurydice_slice_subslice_shared_7e(blocks,
        ((core_ops_range_Range_08){ offset, offset + (size_t)8U })).ptr,
      (size_t)8U * sizeof (uint8_t));
    Eurydice_array_u8x8 uu____0 = unwrap_26_ab((Result_8e){ .tag = Ok, .val = { .case_Ok = arr } });
    state_flat.data[i0] = core_num__u64__from_le_bytes(uu____0);
  }
  for (size_t i = (size_t)0U; i < (size_t)72U / (size_t)8U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_traits_set_ij_04(state,
      i0 / (size_t)5U,
      i0 % (size_t)5U,
      libcrux_sha3_traits_get_ij_04(state, i0 / (size_t)5U, i0 % (size_t)5U)[0U] ^
        state_flat.data[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 72
*/
static inline void
libcrux_sha3_simd_portable_load_block_a1_f8(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_f8(self, input->data[0U], start);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 72
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_block_80_c61(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_a1_f8(self, input, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 72
- DELIMITER= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_last_96(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start,
  size_t len
)
{
  Eurydice_arr_a0 buffer = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_361(&buffer,
      ((core_ops_range_Range_08){ (size_t)0U, len })),
    Eurydice_slice_subslice_shared_7e(blocks, ((core_ops_range_Range_08){ start, start + len })),
    uint8_t);
  buffer.data[len] = 6U;
  size_t uu____0 = (size_t)72U - (size_t)1U;
  buffer.data[uu____0] = (uint32_t)buffer.data[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_f8(state,
    Eurydice_array_to_slice_shared_7d(&buffer),
    (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 72
- DELIMITER= 6
*/
static inline void
libcrux_sha3_simd_portable_load_last_a1_96(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_96(self, input->data[0U], start, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 72
- DELIM= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_final_80_9e1(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_a1_96(self, input, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 72
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_store_block_f8(
  const Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  size_t octets = len / (size_t)8U;
  for (size_t i = (size_t)0U; i < octets; i++)
  {
    size_t i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          i0 / (size_t)5U,
          i0 % (size_t)5U)[0U]);
    size_t out_pos = start + (size_t)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + (size_t)8U })),
      Eurydice_array_to_slice_shared_41(&bytes),
      uint8_t);
  }
  size_t remaining = len % (size_t)8U;
  if (remaining > (size_t)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          octets / (size_t)5U,
          octets % (size_t)5U)[0U]);
    size_t out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_6e(&bytes, remaining),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 72
*/
static inline void
libcrux_sha3_simd_portable_squeeze_9b_f8(
  const Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_store_block_f8(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 72
- DELIM= 6
*/
static inline void
libcrux_sha3_generic_keccak_portable_keccak1_96(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_26 s = libcrux_sha3_generic_keccak_new_80_04();
  size_t input_len = input.meta;
  size_t input_blocks = input_len / (size_t)72U;
  size_t input_rem = input_len % (size_t)72U;
  for (size_t i = (size_t)0U; i < input_blocks; i++)
  {
    size_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_06 lvalue = { { input } };
    libcrux_sha3_generic_keccak_absorb_block_80_c61(&s, &lvalue, i0 * (size_t)72U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e1(&s, &lvalue, input_len - input_rem, input_rem);
  size_t output_len = output.meta;
  size_t output_blocks = output_len / (size_t)72U;
  size_t output_rem = output_len % (size_t)72U;
  if (output_blocks == (size_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_f8(&s, output, (size_t)0U, output_len);
  }
  else
  {
    libcrux_sha3_simd_portable_squeeze_9b_f8(&s, output, (size_t)0U, (size_t)72U);
    for (size_t i = (size_t)1U; i < output_blocks; i++)
    {
      size_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_f8(&s, output, i0 * (size_t)72U, (size_t)72U);
    }
    if (output_rem != (size_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_f8(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 512 implementation.
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_sha512(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 data
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_96(data, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_last_ad0(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start,
  size_t len
)
{
  Eurydice_arr_3d buffer = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_360(&buffer,
      ((core_ops_range_Range_08){ (size_t)0U, len })),
    Eurydice_slice_subslice_shared_7e(blocks, ((core_ops_range_Range_08){ start, start + len })),
    uint8_t);
  buffer.data[len] = 6U;
  size_t uu____0 = (size_t)136U - (size_t)1U;
  buffer.data[uu____0] = (uint32_t)buffer.data[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_5b(state,
    Eurydice_array_to_slice_shared_d4(&buffer),
    (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 136
- DELIMITER= 6
*/
static inline void
libcrux_sha3_simd_portable_load_last_a1_ad0(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_ad0(self, input->data[0U], start, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
- DELIM= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_final_80_9e2(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_a1_ad0(self, input, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 6
*/
static inline void
libcrux_sha3_generic_keccak_portable_keccak1_ad0(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_26 s = libcrux_sha3_generic_keccak_new_80_04();
  size_t input_len = input.meta;
  size_t input_blocks = input_len / (size_t)136U;
  size_t input_rem = input_len % (size_t)136U;
  for (size_t i = (size_t)0U; i < input_blocks; i++)
  {
    size_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_06 lvalue = { { input } };
    libcrux_sha3_generic_keccak_absorb_block_80_c60(&s, &lvalue, i0 * (size_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e2(&s, &lvalue, input_len - input_rem, input_rem);
  size_t output_len = output.meta;
  size_t output_blocks = output_len / (size_t)136U;
  size_t output_rem = output_len % (size_t)136U;
  if (output_blocks == (size_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, (size_t)0U, output_len);
  }
  else
  {
    libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, (size_t)0U, (size_t)136U);
    for (size_t i = (size_t)1U; i < output_blocks; i++)
    {
      size_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, i0 * (size_t)136U, (size_t)136U);
    }
    if (output_rem != (size_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_5b(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 256 implementation.
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_sha256(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 data
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_ad0(data, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_three_blocks_b4
with const generics
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_portable_squeeze_first_three_blocks_b4_3a(
  Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)0U, (size_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)168U, (size_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
  libcrux_sha3_simd_portable_squeeze_9b_3a(self, out, (size_t)2U * (size_t)168U, (size_t)168U);
}

/**
 Squeeze three blocks
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(
  Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_first_three_blocks_b4_3a(s, out0);
}

#define libcrux_sha3_Algorithm_Sha224 1
#define libcrux_sha3_Algorithm_Sha256 2
#define libcrux_sha3_Algorithm_Sha384 3
#define libcrux_sha3_Algorithm_Sha512 4

typedef uint8_t libcrux_sha3_Algorithm;

#define LIBCRUX_SHA3_SHA3_224_DIGEST_SIZE ((size_t)28U)

#define LIBCRUX_SHA3_SHA3_256_DIGEST_SIZE ((size_t)32U)

#define LIBCRUX_SHA3_SHA3_384_DIGEST_SIZE ((size_t)48U)

#define LIBCRUX_SHA3_SHA3_512_DIGEST_SIZE ((size_t)64U)

/**
 Returns the output size of a digest.
*/
static inline size_t libcrux_sha3_digest_size(libcrux_sha3_Algorithm mode)
{
  switch (mode)
  {
    case libcrux_sha3_Algorithm_Sha224:
      {
        break;
      }
    case libcrux_sha3_Algorithm_Sha256:
      {
        return LIBCRUX_SHA3_SHA3_256_DIGEST_SIZE;
      }
    case libcrux_sha3_Algorithm_Sha384:
      {
        return LIBCRUX_SHA3_SHA3_384_DIGEST_SIZE;
      }
    case libcrux_sha3_Algorithm_Sha512:
      {
        return LIBCRUX_SHA3_SHA3_512_DIGEST_SIZE;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  return LIBCRUX_SHA3_SHA3_224_DIGEST_SIZE;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 144
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_block_2c(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start
)
{
  Eurydice_arr_26 state_flat = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)144U / (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t offset = start + (size_t)8U * i0;
    Eurydice_array_u8x8 arr;
    memcpy(arr.data,
      Eurydice_slice_subslice_shared_7e(blocks,
        ((core_ops_range_Range_08){ offset, offset + (size_t)8U })).ptr,
      (size_t)8U * sizeof (uint8_t));
    Eurydice_array_u8x8 uu____0 = unwrap_26_ab((Result_8e){ .tag = Ok, .val = { .case_Ok = arr } });
    state_flat.data[i0] = core_num__u64__from_le_bytes(uu____0);
  }
  for (size_t i = (size_t)0U; i < (size_t)144U / (size_t)8U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_traits_set_ij_04(state,
      i0 / (size_t)5U,
      i0 % (size_t)5U,
      libcrux_sha3_traits_get_ij_04(state, i0 / (size_t)5U, i0 % (size_t)5U)[0U] ^
        state_flat.data[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 144
*/
static inline void
libcrux_sha3_simd_portable_load_block_a1_2c(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_2c(self, input->data[0U], start);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 144
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_block_80_c62(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_a1_2c(self, input, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 144
- DELIMITER= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_last_1e(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start,
  size_t len
)
{
  Eurydice_arr_a8 buffer = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_362(&buffer,
      ((core_ops_range_Range_08){ (size_t)0U, len })),
    Eurydice_slice_subslice_shared_7e(blocks, ((core_ops_range_Range_08){ start, start + len })),
    uint8_t);
  buffer.data[len] = 6U;
  size_t uu____0 = (size_t)144U - (size_t)1U;
  buffer.data[uu____0] = (uint32_t)buffer.data[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_2c(state,
    Eurydice_array_to_slice_shared_d1(&buffer),
    (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 144
- DELIMITER= 6
*/
static inline void
libcrux_sha3_simd_portable_load_last_a1_1e(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_1e(self, input->data[0U], start, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 144
- DELIM= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_final_80_9e3(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_a1_1e(self, input, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 144
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_store_block_2c(
  const Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  size_t octets = len / (size_t)8U;
  for (size_t i = (size_t)0U; i < octets; i++)
  {
    size_t i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          i0 / (size_t)5U,
          i0 % (size_t)5U)[0U]);
    size_t out_pos = start + (size_t)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + (size_t)8U })),
      Eurydice_array_to_slice_shared_41(&bytes),
      uint8_t);
  }
  size_t remaining = len % (size_t)8U;
  if (remaining > (size_t)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          octets / (size_t)5U,
          octets % (size_t)5U)[0U]);
    size_t out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_6e(&bytes, remaining),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 144
*/
static inline void
libcrux_sha3_simd_portable_squeeze_9b_2c(
  const Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_store_block_2c(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 144
- DELIM= 6
*/
static inline void
libcrux_sha3_generic_keccak_portable_keccak1_1e(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_26 s = libcrux_sha3_generic_keccak_new_80_04();
  size_t input_len = input.meta;
  size_t input_blocks = input_len / (size_t)144U;
  size_t input_rem = input_len % (size_t)144U;
  for (size_t i = (size_t)0U; i < input_blocks; i++)
  {
    size_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_06 lvalue = { { input } };
    libcrux_sha3_generic_keccak_absorb_block_80_c62(&s, &lvalue, i0 * (size_t)144U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e3(&s, &lvalue, input_len - input_rem, input_rem);
  size_t output_len = output.meta;
  size_t output_blocks = output_len / (size_t)144U;
  size_t output_rem = output_len % (size_t)144U;
  if (output_blocks == (size_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_2c(&s, output, (size_t)0U, output_len);
  }
  else
  {
    libcrux_sha3_simd_portable_squeeze_9b_2c(&s, output, (size_t)0U, (size_t)144U);
    for (size_t i = (size_t)1U; i < output_blocks; i++)
    {
      size_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_2c(&s, output, i0 * (size_t)144U, (size_t)144U);
    }
    if (output_rem != (size_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_2c(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 224 implementation.
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_sha224(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 data
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_1e(data, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 104
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_block_7a(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start
)
{
  Eurydice_arr_26 state_flat = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)104U / (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t offset = start + (size_t)8U * i0;
    Eurydice_array_u8x8 arr;
    memcpy(arr.data,
      Eurydice_slice_subslice_shared_7e(blocks,
        ((core_ops_range_Range_08){ offset, offset + (size_t)8U })).ptr,
      (size_t)8U * sizeof (uint8_t));
    Eurydice_array_u8x8 uu____0 = unwrap_26_ab((Result_8e){ .tag = Ok, .val = { .case_Ok = arr } });
    state_flat.data[i0] = core_num__u64__from_le_bytes(uu____0);
  }
  for (size_t i = (size_t)0U; i < (size_t)104U / (size_t)8U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_traits_set_ij_04(state,
      i0 / (size_t)5U,
      i0 % (size_t)5U,
      libcrux_sha3_traits_get_ij_04(state, i0 / (size_t)5U, i0 % (size_t)5U)[0U] ^
        state_flat.data[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 104
*/
static inline void
libcrux_sha3_simd_portable_load_block_a1_7a(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_7a(self, input->data[0U], start);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 104
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_block_80_c63(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start
)
{
  libcrux_sha3_simd_portable_load_block_a1_7a(self, input, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 104
- DELIMITER= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_load_last_7c(
  Eurydice_arr_26 *state,
  Eurydice_borrow_slice_u8 blocks,
  size_t start,
  size_t len
)
{
  Eurydice_arr_18 buffer = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_363(&buffer,
      ((core_ops_range_Range_08){ (size_t)0U, len })),
    Eurydice_slice_subslice_shared_7e(blocks, ((core_ops_range_Range_08){ start, start + len })),
    uint8_t);
  buffer.data[len] = 6U;
  size_t uu____0 = (size_t)104U - (size_t)1U;
  buffer.data[uu____0] = (uint32_t)buffer.data[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_7a(state,
    Eurydice_array_to_slice_shared_9c(&buffer),
    (size_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 104
- DELIMITER= 6
*/
static inline void
libcrux_sha3_simd_portable_load_last_a1_7c(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_7c(self, input->data[0U], start, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 104
- DELIM= 6
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_absorb_final_80_9e4(
  Eurydice_arr_26 *self,
  const Eurydice_arr_06 *input,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_load_last_a1_7c(self, input, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 104
*/
static KRML_MUSTINLINE void
libcrux_sha3_simd_portable_store_block_7a(
  const Eurydice_arr_26 *s,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  size_t octets = len / (size_t)8U;
  for (size_t i = (size_t)0U; i < octets; i++)
  {
    size_t i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          i0 / (size_t)5U,
          i0 % (size_t)5U)[0U]);
    size_t out_pos = start + (size_t)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + (size_t)8U })),
      Eurydice_array_to_slice_shared_41(&bytes),
      uint8_t);
  }
  size_t remaining = len % (size_t)8U;
  if (remaining > (size_t)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_num__u64__to_le_bytes(libcrux_sha3_traits_get_ij_04(s,
          octets / (size_t)5U,
          octets % (size_t)5U)[0U]);
    size_t out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        ((core_ops_range_Range_08){ out_pos, out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_6e(&bytes, remaining),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 104
*/
static inline void
libcrux_sha3_simd_portable_squeeze_9b_7a(
  const Eurydice_arr_26 *self,
  Eurydice_mut_borrow_slice_u8 out,
  size_t start,
  size_t len
)
{
  libcrux_sha3_simd_portable_store_block_7a(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 104
- DELIM= 6
*/
static inline void
libcrux_sha3_generic_keccak_portable_keccak1_7c(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_26 s = libcrux_sha3_generic_keccak_new_80_04();
  size_t input_len = input.meta;
  size_t input_blocks = input_len / (size_t)104U;
  size_t input_rem = input_len % (size_t)104U;
  for (size_t i = (size_t)0U; i < input_blocks; i++)
  {
    size_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_06 lvalue = { { input } };
    libcrux_sha3_generic_keccak_absorb_block_80_c63(&s, &lvalue, i0 * (size_t)104U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_absorb_final_80_9e4(&s, &lvalue, input_len - input_rem, input_rem);
  size_t output_len = output.meta;
  size_t output_blocks = output_len / (size_t)104U;
  size_t output_rem = output_len % (size_t)104U;
  if (output_blocks == (size_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_7a(&s, output, (size_t)0U, output_len);
  }
  else
  {
    libcrux_sha3_simd_portable_squeeze_9b_7a(&s, output, (size_t)0U, (size_t)104U);
    for (size_t i = (size_t)1U; i < output_blocks; i++)
    {
      size_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_7a(&s, output, i0 * (size_t)104U, (size_t)104U);
    }
    if (output_rem != (size_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&s);
      libcrux_sha3_simd_portable_squeeze_9b_7a(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 384 implementation.
*/
static KRML_MUSTINLINE void
libcrux_sha3_portable_sha384(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 data
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_7c(data, digest);
}

/**
 SHA3 224

 Preconditions:
 - `digest.len() == 28`
*/
static inline void
libcrux_sha3_sha224_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha224(digest, payload);
}

/**
 SHA3 224
*/
static inline Eurydice_arr_f1 libcrux_sha3_sha224(Eurydice_borrow_slice_u8 data)
{
  Eurydice_arr_f1 out = { { 0U } };
  libcrux_sha3_sha224_ema(Eurydice_array_to_slice_mut_c0(&out), data);
  return out;
}

/**
 SHA3 256
*/
static inline void
libcrux_sha3_sha256_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha256(digest, payload);
}

/**
 SHA3 256
*/
static inline Eurydice_arr_600 libcrux_sha3_sha256(Eurydice_borrow_slice_u8 data)
{
  Eurydice_arr_600 out = { { 0U } };
  libcrux_sha3_sha256_ema(Eurydice_array_to_slice_mut_6e(&out), data);
  return out;
}

/**
 SHA3 384
*/
static inline void
libcrux_sha3_sha384_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha384(digest, payload);
}

/**
 SHA3 384
*/
static inline Eurydice_arr_5f libcrux_sha3_sha384(Eurydice_borrow_slice_u8 data)
{
  Eurydice_arr_5f out = { { 0U } };
  libcrux_sha3_sha384_ema(Eurydice_array_to_slice_mut_95(&out), data);
  return out;
}

/**
 SHA3 512
*/
static inline void
libcrux_sha3_sha512_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha512(digest, payload);
}

/**
 SHA3 512
*/
static inline Eurydice_arr_060 libcrux_sha3_sha512(Eurydice_borrow_slice_u8 data)
{
  Eurydice_arr_060 out = { { 0U } };
  libcrux_sha3_sha512_ema(Eurydice_array_to_slice_mut_d8(&out), data);
  return out;
}

/**
 SHAKE 128

 Writes `out.len()` bytes.
*/
static inline void
libcrux_sha3_shake128_ema(Eurydice_mut_borrow_slice_u8 out, Eurydice_borrow_slice_u8 data)
{
  libcrux_sha3_portable_shake128(out, data);
}

/**
 SHAKE 256

 Writes `out.len()` bytes.
*/
static inline void
libcrux_sha3_shake256_ema(Eurydice_mut_borrow_slice_u8 out, Eurydice_borrow_slice_u8 data)
{
  libcrux_sha3_portable_shake256(out, data);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $168size_t
*/
typedef struct libcrux_sha3_generic_keccak_xof_KeccakXofState_97_s
{
  Eurydice_arr_26 inner;
  Eurydice_arr_3a buf;
  size_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_97;

typedef libcrux_sha3_generic_keccak_xof_KeccakXofState_97
libcrux_sha3_portable_incremental_Shake128Xof;

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.fill_buffer_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static inline size_t
libcrux_sha3_generic_keccak_xof_fill_buffer_35_c60(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  const Eurydice_arr_06 *inputs
)
{
  size_t input_len = inputs->data->meta;
  size_t uu____0;
  if (self->buf_len != (size_t)0U)
  {
    if (input_len >= (size_t)168U - self->buf_len)
    {
      size_t consumed = (size_t)168U - self->buf_len;
      for (size_t i = (size_t)0U; i < (size_t)1U; i++)
      {
        size_t i0 = i;
        Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_8c0(&self->buf.data[i0],
            self->buf_len),
          Eurydice_slice_subslice_to_shared_c6(inputs->data[i0], consumed),
          uint8_t);
      }
      self->buf_len = (size_t)168U;
      uu____0 = consumed;
    }
    else
    {
      uu____0 = (size_t)0U;
    }
  }
  else
  {
    uu____0 = (size_t)0U;
  }
  return uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $168size_t
*/
typedef const Eurydice_arr_3a *libcrux_sha3_generic_keccak_xof_buf_to_slices_closure_21;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ (@Slice<u8>)> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_a7
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static inline Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_a7_5b0(
  const Eurydice_arr_3a **_,
  size_t tupled_args
)
{
  size_t i = tupled_args;
  return
    core_array___Array_T__N___as_slice((size_t)168U,
      &_[0U]->data[i],
      uint8_t,
      Eurydice_borrow_slice_u8);
}

/**
This function found in impl {core::ops::function::FnOnce<(usize), &'_ (@Slice<u8>)> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_once_2d
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static inline Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_once_2d_5b0(
  const Eurydice_arr_3a *_,
  size_t _0
)
{
  return libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_a7_5b0(&_, _0);
}

/**
 Note: This function exists to work around a hax bug where `core::array::from_fn`
 is extracted with an incorrect explicit type parameter `#(usize -> t_Slice u8)`
 instead of using the typeclass-based implicit parameter `#v_F` from
 `Core_models.Array.from_fn`.
 See: https://github.com/cryspen/hax/issues/1920
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static KRML_MUSTINLINE Eurydice_arr_06
libcrux_sha3_generic_keccak_xof_buf_to_slices_5b0(const Eurydice_arr_3a *buf)
{
  Eurydice_arr_06 arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)1U; i++)
  {
    arr_struct.data[i] = libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_a7_5b0(&buf, i);
  }
  return arr_struct;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_full_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static inline size_t
libcrux_sha3_generic_keccak_xof_absorb_full_35_c60(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  const Eurydice_arr_06 *inputs
)
{
  size_t consumed = libcrux_sha3_generic_keccak_xof_fill_buffer_35_c60(self, inputs);
  if (self->buf_len == (size_t)168U)
  {
    Eurydice_arr_06 borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_5b0(&self->buf);
    libcrux_sha3_simd_portable_load_block_a1_3a(&self->inner, &borrowed, (size_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
    self->buf_len = (size_t)0U;
  }
  size_t input_to_consume = inputs->data->meta - consumed;
  size_t num_blocks = input_to_consume / (size_t)168U;
  size_t remainder = input_to_consume % (size_t)168U;
  for (size_t i = (size_t)0U; i < num_blocks; i++)
  {
    size_t i0 = i;
    size_t start = i0 * (size_t)168U + consumed;
    libcrux_sha3_simd_portable_load_block_a1_3a(&self->inner, inputs, start);
    libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
  }
  return remainder;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_xof_absorb_35_c60(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  const Eurydice_arr_06 *inputs
)
{
  size_t remainder = libcrux_sha3_generic_keccak_xof_absorb_full_35_c60(self, inputs);
  if (remainder > (size_t)0U)
  {
    size_t input_len = inputs->data->meta;
    for (size_t i = (size_t)0U; i < (size_t)1U; i++)
    {
      size_t i0 = i;
      Eurydice_slice_copy(Eurydice_array_to_subslice_mut_36(&self->buf.data[i0],
          ((core_ops_range_Range_08){ self->buf_len, self->buf_len + remainder })),
        Eurydice_slice_subslice_shared_7e(inputs->data[i0],
          ((core_ops_range_Range_08){ input_len - remainder, input_len })),
        uint8_t);
    }
    self->buf_len = self->buf_len + remainder;
  }
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
static inline void
libcrux_sha3_portable_incremental_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  Eurydice_borrow_slice_u8 input
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_xof_absorb_35_c60(self, &lvalue);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_final_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
- DELIMITER= 31
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_xof_absorb_final_35_9e0(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  const Eurydice_arr_06 *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_c60(self, inputs);
  Eurydice_arr_06 borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_5b0(&self->buf);
  libcrux_sha3_simd_portable_load_last_a1_c6(&self->inner, &borrowed, (size_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
static inline void
libcrux_sha3_portable_incremental_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  Eurydice_borrow_slice_u8 input
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_06 lvalue = { { input } };
  libcrux_sha3_generic_keccak_xof_absorb_final_35_9e0(self, &lvalue);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.zero_block_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static inline Eurydice_arr_27 libcrux_sha3_generic_keccak_xof_zero_block_35_c60(void)
{
  return ((Eurydice_arr_27){ { 0U } });
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.new_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
static inline libcrux_sha3_generic_keccak_xof_KeccakXofState_97
libcrux_sha3_generic_keccak_xof_new_35_c60(void)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_04();
  Eurydice_arr_27 repeat_expression[1U];
  for (size_t i = (size_t)0U; i < (size_t)1U; i++)
  {
    repeat_expression[i] = libcrux_sha3_generic_keccak_xof_zero_block_35_c60();
  }
  memcpy(lit.buf.data, repeat_expression, (size_t)1U * sizeof (Eurydice_arr_27));
  lit.buf_len = (size_t)0U;
  lit.sponge = false;
  return lit;
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
static inline libcrux_sha3_generic_keccak_xof_KeccakXofState_97
libcrux_sha3_portable_incremental_new_26(void)
{
  return libcrux_sha3_generic_keccak_xof_new_35_c60();
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, 1usize, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.squeeze_85
with types uint64_t
with const generics
- RATE= 168
*/
static KRML_MUSTINLINE void
libcrux_sha3_generic_keccak_xof_squeeze_85_13(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  size_t out_len = out.meta;
  if (!(out_len == (size_t)0U))
  {
    if (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
    }
    if (out_len > (size_t)0U)
    {
      size_t blocks = out_len / (size_t)168U;
      size_t last = out_len - out_len % (size_t)168U;
      if (blocks == (size_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_3a(&self->inner, out, (size_t)0U, out_len);
      }
      else
      {
        libcrux_sha3_simd_portable_squeeze_9b_3a(&self->inner, out, (size_t)0U, (size_t)168U);
        for (size_t i = (size_t)1U; i < blocks; i++)
        {
          size_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_3a(&self->inner,
            out,
            i0 * (size_t)168U,
            (size_t)168U);
        }
        if (last < out_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_3a(&self->inner, out, last, out_len - last);
        }
      }
    }
    self->sponge = true;
  }
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
static inline void
libcrux_sha3_portable_incremental_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_97 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_13(self, out);
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::portable::KeccakState}
*/
static inline Eurydice_arr_26 libcrux_sha3_portable_clone_fe(const Eurydice_arr_26 *self)
{
  return self[0U];
}

/**
This function found in impl {core::convert::From<libcrux_sha3::Algorithm> for u32}
*/
static inline uint32_t libcrux_sha3_from_6c(libcrux_sha3_Algorithm v)
{
  switch (v)
  {
    case libcrux_sha3_Algorithm_Sha224:
      {
        break;
      }
    case libcrux_sha3_Algorithm_Sha256:
      {
        return 2U;
      }
    case libcrux_sha3_Algorithm_Sha384:
      {
        return 3U;
      }
    case libcrux_sha3_Algorithm_Sha512:
      {
        return 4U;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  return 1U;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_sha3_portable_KeccakState
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_e4_s { Eurydice_arr_26 data[3U]; } Eurydice_arr_e4;


#define libcrux_sha3_portable_H_DEFINED
#endif /* libcrux_sha3_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_mldsa_core_H
#define libcrux_mldsa_core_H





#define libcrux_ml_dsa_types_VerificationError_MalformedHintError 0
#define libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError 1
#define libcrux_ml_dsa_types_VerificationError_CommitmentHashesDontMatchError 2
#define libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError 3

typedef uint8_t libcrux_ml_dsa_types_VerificationError;

#define libcrux_ml_dsa_types_SigningError_RejectionSamplingError 0
#define libcrux_ml_dsa_types_SigningError_ContextTooLongError 1

typedef uint8_t libcrux_ml_dsa_types_SigningError;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASignature
with const generics
- $3309size_t
*/
typedef Eurydice_arr_96 libcrux_ml_dsa_types_MLDSASignature_8f;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 3309
*/
static inline const
Eurydice_arr_96
*libcrux_ml_dsa_types_as_ref_c5_fa(const Eurydice_arr_96 *self)
{
  return self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 1952
*/
static inline const
Eurydice_arr_4a
*libcrux_ml_dsa_types_as_ref_7f_97(const Eurydice_arr_4a *self)
{
  return self;
}

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_VerificationError

*/
typedef struct Result_41_s
{
  Result_80_tags tag;
  libcrux_ml_dsa_types_VerificationError f0;
}
Result_41;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 4032
*/
static inline const
Eurydice_arr_d10
*libcrux_ml_dsa_types_as_ref_9b_09(const Eurydice_arr_d10 *self)
{
  return self;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_types_MLDSASignature_8f, libcrux_ml_dsa_types_SigningError

*/
typedef struct Result_97_s
{
  Result_80_tags tag;
  union {
    Eurydice_arr_96 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_97_s)
}
Result_97;

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_SigningError

*/
typedef struct Result_53_s
{
  Result_80_tags tag;
  libcrux_ml_dsa_types_SigningError f0;
}
Result_53;

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 3309
*/
static inline Eurydice_arr_96 libcrux_ml_dsa_types_zero_c5_fa(void)
{
  return ((Eurydice_arr_96){ { 0U } });
}

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAKeyPair
with const generics
- $1952size_t
- $4032size_t
*/
typedef struct libcrux_ml_dsa_types_MLDSAKeyPair_06_s
{
  Eurydice_arr_d10 signing_key;
  Eurydice_arr_4a verification_key;
}
libcrux_ml_dsa_types_MLDSAKeyPair_06;

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 1952
*/
static inline Eurydice_arr_4a libcrux_ml_dsa_types_new_7f_97(Eurydice_arr_4a value)
{
  return value;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 4032
*/
static inline Eurydice_arr_d10 libcrux_ml_dsa_types_new_9b_09(Eurydice_arr_d10 value)
{
  return value;
}


#define libcrux_mldsa_core_H_DEFINED
#endif /* libcrux_mldsa_core_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa65_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_mldsa65_portable_H
#define libcrux_mldsa65_portable_H





#define libcrux_ml_dsa_constants_Eta_Two 2
#define libcrux_ml_dsa_constants_Eta_Four 4

typedef uint8_t libcrux_ml_dsa_constants_Eta;

#define LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT ((size_t)8U)

#define LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_IN_RING_ELEMENT ((size_t)32U)

#define LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T ((size_t)13U)

#define LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS_MINUS_ONE_BIT_LENGTH ((size_t)23U)

#define LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_UPPER_PART_OF_T (LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS_MINUS_ONE_BIT_LENGTH - LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T)

#define LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_KEY_HASH ((size_t)64U)

#define LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT ((size_t)256U)

#define LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN ((size_t)255U)

#define LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS ((int32_t)8380417)

#define LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V261_888 ((int32_t)261888)

#define LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V95_232 ((int32_t)95232)

typedef int32_t libcrux_ml_dsa_constants_Gamma2;

#define LIBCRUX_ML_DSA_CONSTANTS_KEY_GENERATION_RANDOMNESS_SIZE ((size_t)32U)

#define LIBCRUX_ML_DSA_CONSTANTS_MASK_SEED_SIZE ((size_t)64U)

#define LIBCRUX_ML_DSA_CONSTANTS_MESSAGE_REPRESENTATIVE_SIZE ((size_t)64U)

#define LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN ((size_t)814U)

#define LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE (LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (size_t)8U)

#define LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1S_SIZE (LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_UPPER_PART_OF_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (size_t)8U)

#define LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE ((size_t)32U)

#define LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_ERROR_VECTORS_SIZE ((size_t)64U)

#define LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_SIZE ((size_t)32U)

#define LIBCRUX_ML_DSA_CONSTANTS_SIGNING_RANDOMNESS_SIZE ((size_t)32U)

static inline int32_t
libcrux_ml_dsa_constants_beta(
  size_t ones_in_verifier_challenge,
  libcrux_ml_dsa_constants_Eta eta
)
{
  size_t eta_val;
  switch (eta)
  {
    case libcrux_ml_dsa_constants_Eta_Two:
      {
        eta_val = (size_t)2U;
        break;
      }
    case libcrux_ml_dsa_constants_Eta_Four:
      {
        eta_val = (size_t)4U;
        break;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  return (int32_t)(ones_in_verifier_challenge * eta_val);
}

static inline size_t
libcrux_ml_dsa_constants_commitment_ring_element_size(size_t bits_per_commitment_coefficient)
{
  return
    bits_per_commitment_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT /
      (size_t)8U;
}

static inline size_t
libcrux_ml_dsa_constants_commitment_vector_size(
  size_t bits_per_commitment_coefficient,
  size_t rows_in_a
)
{
  return
    libcrux_ml_dsa_constants_commitment_ring_element_size(bits_per_commitment_coefficient) *
      rows_in_a;
}

static inline size_t
libcrux_ml_dsa_constants_error_ring_element_size(size_t bits_per_error_coefficient)
{
  return
    bits_per_error_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (size_t)8U;
}

static inline size_t
libcrux_ml_dsa_constants_gamma1_ring_element_size(size_t bits_per_gamma1_coefficient)
{
  return
    bits_per_gamma1_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT /
      (size_t)8U;
}

static inline size_t
libcrux_ml_dsa_constants_signature_size(
  size_t rows_in_a,
  size_t columns_in_a,
  size_t max_ones_in_hint,
  size_t commitment_hash_size,
  size_t bits_per_gamma1_coefficient
)
{
  return
    commitment_hash_size +
      columns_in_a * libcrux_ml_dsa_constants_gamma1_ring_element_size(bits_per_gamma1_coefficient)
    + max_ones_in_hint
    + rows_in_a;
}

static inline size_t
libcrux_ml_dsa_constants_signing_key_size(
  size_t rows_in_a,
  size_t columns_in_a,
  size_t error_ring_element_size
)
{
  return
    LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_SIZE +
      LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_KEY_HASH
    + (rows_in_a + columns_in_a) * error_ring_element_size
    + rows_in_a * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE;
}

static inline size_t libcrux_ml_dsa_constants_verification_key_size(size_t rows_in_a)
{
  return
    LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE +
      LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * rows_in_a *
        (LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS_MINUS_ONE_BIT_LENGTH -
          LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T)
      / (size_t)8U;
}

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_COMMITMENT_COEFFICIENT ((size_t)4U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_ERROR_COEFFICIENT ((size_t)4U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_GAMMA1_COEFFICIENT ((size_t)20U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A ((size_t)5U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_SIZE ((size_t)48U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA (libcrux_ml_dsa_constants_Eta_Four)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT ((size_t)19U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS - (int32_t)1) / (int32_t)32)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT ((size_t)55U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE ((size_t)49U)

#define LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A ((size_t)6U)

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::constants::Eta}
*/
static inline libcrux_ml_dsa_constants_Eta
libcrux_ml_dsa_constants_clone_54(const libcrux_ml_dsa_constants_Eta *self)
{
  return self[0U];
}

static KRML_MUSTINLINE size_t
libcrux_ml_dsa_encoding_error_chunk_size(libcrux_ml_dsa_constants_Eta eta)
{
  switch (eta)
  {
    case libcrux_ml_dsa_constants_Eta_Two:
      {
        break;
      }
    case libcrux_ml_dsa_constants_Eta_Four:
      {
        return (size_t)4U;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  return (size_t)3U;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_signature_set_hint(
  Eurydice_dst_ref_mut_22 out_hint,
  size_t i,
  size_t j
)
{
  out_hint.ptr[i].data[j] = (int32_t)1;
}

#define LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT ((size_t)13U)

#define LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_WINDOW ((size_t)10U)

#define LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_BYTES_PER_SIMD_UNIT ((size_t)10U)

typedef struct libcrux_ml_dsa_hash_functions_portable_Shake128X4_s
{
  Eurydice_arr_26 state0;
  Eurydice_arr_26 state1;
  Eurydice_arr_26 state2;
  Eurydice_arr_26 state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake128X4;

typedef libcrux_sha3_portable_KeccakState libcrux_ml_dsa_hash_functions_portable_Shake256;

typedef struct libcrux_ml_dsa_hash_functions_portable_Shake256X4_s
{
  Eurydice_arr_26 state0;
  Eurydice_arr_26 state1;
  Eurydice_arr_26 state2;
  Eurydice_arr_26 state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake256X4;

typedef libcrux_sha3_portable_incremental_Shake256Xof
libcrux_ml_dsa_hash_functions_portable_Shake256Xof;

static KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
)
{
  Eurydice_arr_26 state0 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state0, input0);
  Eurydice_arr_26 state1 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state1, input1);
  Eurydice_arr_26 state2 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state2, input2);
  Eurydice_arr_26 state3 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state3, input3);
  return ((libcrux_ml_dsa_hash_functions_portable_Shake128X4){ state0, state1, state2, state3 });
}

static KRML_MUSTINLINE Eurydice_arr_26
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(
  Eurydice_borrow_slice_u8 input
)
{
  Eurydice_arr_26 state = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state, input);
  return state;
}

static KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
)
{
  Eurydice_arr_26 state0 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state0, input0);
  Eurydice_arr_26 state1 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state1, input1);
  Eurydice_arr_26 state2 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state2, input2);
  Eurydice_arr_26 state3 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state3, input3);
  return ((libcrux_ml_dsa_hash_functions_portable_Shake256X4){ state0, state1, state2, state3 });
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake128(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_portable_shake128(out, input);
}

static KRML_MUSTINLINE Eurydice_arr_3d
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_shake256(Eurydice_arr_26 *state)
{
  Eurydice_arr_3d out = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(state,
    Eurydice_array_to_slice_mut_d4(&out));
  return out;
}

typedef struct Eurydice_arr_3d_x4_s
{
  Eurydice_arr_3d fst;
  Eurydice_arr_3d snd;
  Eurydice_arr_3d thd;
  Eurydice_arr_3d f3;
}
Eurydice_arr_3d_x4;

static KRML_MUSTINLINE Eurydice_arr_3d_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_3d out0 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state0,
    Eurydice_array_to_slice_mut_d4(&out0));
  Eurydice_arr_3d out1 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state1,
    Eurydice_array_to_slice_mut_d4(&out1));
  Eurydice_arr_3d out2 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state2,
    Eurydice_array_to_slice_mut_d4(&out2));
  Eurydice_arr_3d out3 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state3,
    Eurydice_array_to_slice_mut_d4(&out3));
  return ((Eurydice_arr_3d_x4){ out0, out1, out2, out3 });
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state,
  Eurydice_arr_12 *out0,
  Eurydice_arr_12 *out1,
  Eurydice_arr_12 *out2,
  Eurydice_arr_12 *out3
)
{
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state0,
    Eurydice_array_to_slice_mut_a8(out0));
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state1,
    Eurydice_array_to_slice_mut_a8(out1));
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state2,
    Eurydice_array_to_slice_mut_a8(out2));
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state3,
    Eurydice_array_to_slice_mut_a8(out3));
}

typedef struct Eurydice_arr_27_x4_s
{
  Eurydice_arr_27 fst;
  Eurydice_arr_27 snd;
  Eurydice_arr_27 thd;
  Eurydice_arr_27 f3;
}
Eurydice_arr_27_x4;

static KRML_MUSTINLINE Eurydice_arr_27_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_next_block(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state
)
{
  Eurydice_arr_27 out0 = { { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_next_block(&state->state0,
    Eurydice_array_to_slice_mut_7b(&out0));
  Eurydice_arr_27 out1 = { { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_next_block(&state->state1,
    Eurydice_array_to_slice_mut_7b(&out1));
  Eurydice_arr_27 out2 = { { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_next_block(&state->state2,
    Eurydice_array_to_slice_mut_7b(&out2));
  Eurydice_arr_27 out3 = { { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_next_block(&state->state3,
    Eurydice_array_to_slice_mut_7b(&out3));
  return ((Eurydice_arr_27_x4){ out0, out1, out2, out3 });
}

static KRML_MUSTINLINE Eurydice_arr_3d
libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_shake256(Eurydice_arr_26 *state)
{
  Eurydice_arr_3d out = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_next_block(state,
    Eurydice_array_to_slice_mut_d4(&out));
  return out;
}

static KRML_MUSTINLINE Eurydice_arr_3d_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_3d out0 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_next_block(&state->state0,
    Eurydice_array_to_slice_mut_d4(&out0));
  Eurydice_arr_3d out1 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_next_block(&state->state1,
    Eurydice_array_to_slice_mut_d4(&out1));
  Eurydice_arr_3d out2 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_next_block(&state->state2,
    Eurydice_array_to_slice_mut_d4(&out2));
  Eurydice_arr_3d out3 = { { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_next_block(&state->state3,
    Eurydice_array_to_slice_mut_d4(&out3));
  return ((Eurydice_arr_3d_x4){ out0, out1, out2, out3 });
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::Xof for libcrux_ml_dsa::hash_functions::portable::Shake128}
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake128_7b(
  Eurydice_borrow_slice_u8 input,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128(input, out);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
static KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_11(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
)
{
  return libcrux_ml_dsa_hash_functions_portable_init_absorb(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self,
  Eurydice_arr_12 *out0,
  Eurydice_arr_12 *out1,
  Eurydice_arr_12 *out2,
  Eurydice_arr_12 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks(self, out0, out1, out2, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
static KRML_MUSTINLINE Eurydice_arr_27_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self
)
{
  return libcrux_ml_dsa_hash_functions_portable_squeeze_next_block(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
static KRML_MUSTINLINE Eurydice_arr_26
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(Eurydice_borrow_slice_u8 input)
{
  return libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(input);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
static KRML_MUSTINLINE Eurydice_arr_3d
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_61(Eurydice_arr_26 *self)
{
  return libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
static KRML_MUSTINLINE Eurydice_arr_3d
libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_61(Eurydice_arr_26 *self)
{
  return libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
static inline void
libcrux_ml_dsa_hash_functions_portable_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_borrow_slice_u8 input
)
{
  libcrux_sha3_portable_incremental_absorb_42(self, input);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
static inline void
libcrux_ml_dsa_hash_functions_portable_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_borrow_slice_u8 input
)
{
  libcrux_sha3_portable_incremental_absorb_final_42(self, input);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
static inline libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
libcrux_ml_dsa_hash_functions_portable_init_26(void)
{
  return libcrux_sha3_portable_incremental_new_42();
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
static inline void
libcrux_ml_dsa_hash_functions_portable_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_portable_incremental_squeeze_42(self, out);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
static KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
)
{
  return libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
static KRML_MUSTINLINE Eurydice_arr_3d_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  return libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
static KRML_MUSTINLINE Eurydice_arr_3d_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  return libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4(self);
}

#define LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_BLOCK_SIZE ((size_t)168U)

#define LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_FIVE_BLOCKS_SIZE (LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_BLOCK_SIZE * (size_t)5U)

#define LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE256_BLOCK_SIZE ((size_t)136U)

static KRML_MUSTINLINE Eurydice_arr_a2
libcrux_ml_dsa_sample_add_error_domain_separator(
  Eurydice_borrow_slice_u8 slice,
  uint16_t domain_separator
)
{
  Eurydice_arr_a2 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_365(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  out.data[64U] = (uint8_t)domain_separator;
  out.data[65U] = (uint8_t)((uint32_t)domain_separator >> 8U);
  return out;
}

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE (libcrux_ml_dsa_constants_error_ring_element_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_ERROR_COEFFICIENT))

#define LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS ((int32_t)8380417)

#define LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R (58728449ULL)

typedef struct uint8_t_x2_s
{
  uint8_t fst;
  uint8_t snd;
}
uint8_t_x2;

static inline uint8_t_x2
libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(size_t index, size_t width)
{
  return ((uint8_t_x2){ (uint8_t)(index / width), (uint8_t)(index % width) });
}

static KRML_MUSTINLINE uint16_t libcrux_ml_dsa_sample_generate_domain_separator(uint8_t_x2 _)
{
  uint8_t row = _.fst;
  uint8_t column = _.snd;
  return (uint32_t)(uint16_t)column | (uint32_t)(uint16_t)row << 8U;
}

static KRML_MUSTINLINE Eurydice_arr_48
libcrux_ml_dsa_sample_add_domain_separator(Eurydice_borrow_slice_u8 slice, uint8_t_x2 indices)
{
  Eurydice_arr_48 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_366(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  uint16_t domain_separator = libcrux_ml_dsa_sample_generate_domain_separator(indices);
  out.data[32U] = (uint8_t)domain_separator;
  out.data[33U] = (uint8_t)((uint32_t)domain_separator >> 8U);
  return out;
}

typedef struct libcrux_ml_dsa_pre_hash_DomainSeparationContext_s
{
  Eurydice_borrow_slice_u8 context;
  Option_b5 pre_hash_oid;
}
libcrux_ml_dsa_pre_hash_DomainSeparationContext;

#define libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError 0

typedef uint8_t libcrux_ml_dsa_pre_hash_DomainSeparationError;

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext, libcrux_ml_dsa_pre_hash_DomainSeparationError

*/
typedef struct Result_a8_s
{
  Result_80_tags tag;
  union {
    libcrux_ml_dsa_pre_hash_DomainSeparationContext case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationError case_Err;
  }
  val;
  KRML_UNION_CONSTRUCTOR(Result_a8_s)
}
Result_a8;

/**
 `context` must be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
static inline Result_a8
libcrux_ml_dsa_pre_hash_new_88(Eurydice_borrow_slice_u8 context, Option_b5 pre_hash_oid)
{
  if (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    return (Result_a8){ .tag = Ok, .val = { .case_Ok = { context, pre_hash_oid } } };
  }
  return
    (Result_a8){ .tag = Err, .val = { .case_Err = libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError } };
}

/**
 Returns the pre-hash OID, if any.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
static inline const
Option_b5
*libcrux_ml_dsa_pre_hash_pre_hash_oid_88(
  const libcrux_ml_dsa_pre_hash_DomainSeparationContext *self
)
{
  return &self->pre_hash_oid;
}

/**
 Returns the context, guaranteed to be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
static inline Eurydice_borrow_slice_u8
libcrux_ml_dsa_pre_hash_context_88(const libcrux_ml_dsa_pre_hash_DomainSeparationContext *self)
{
  return self->context;
}

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_SIZE (libcrux_ml_dsa_constants_commitment_ring_element_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_COMMITMENT_COEFFICIENT))

static KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_inside_out_shuffle(
  Eurydice_borrow_slice_u8 randomness,
  size_t *out_index,
  uint64_t *signs,
  Eurydice_arr_c3 *result
)
{
  bool done = false;
  for (size_t i = (size_t)0U; i < randomness.meta; i++)
  {
    size_t _cloop_j = i;
    const uint8_t *byte = &randomness.ptr[_cloop_j];
    if (!done)
    {
      size_t sample_at = (size_t)byte[0U];
      if (sample_at <= out_index[0U])
      {
        result->data[out_index[0U]] = result->data[sample_at];
        out_index[0U] = out_index[0U] + (size_t)1U;
        result->data[sample_at] = (int32_t)1 - (int32_t)2 * (int32_t)(signs[0U] & 1ULL);
        signs[0U] = signs[0U] >> 1U;
      }
      done = out_index[0U] == (size_t)256U;
    }
  }
  return done;
}

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA))

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_SIZE (libcrux_ml_dsa_constants_gamma1_ring_element_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_GAMMA1_COEFFICIENT))

#define LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID (((Eurydice_arr_cb){ { 6U, 9U, 96U, 134U, 72U, 1U, 101U, 3U, 4U, 2U, 11U } }))

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
static inline Eurydice_arr_cb libcrux_ml_dsa_pre_hash_oid_30(void)
{
  return LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID;
}

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_KEY_SIZE (libcrux_ml_dsa_constants_verification_key_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A))

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_SIZE (libcrux_ml_dsa_constants_signature_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_SIZE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_GAMMA1_COEFFICIENT))

typedef Eurydice_arr_d4 libcrux_ml_dsa_simd_portable_vector_type_Coefficients;

static KRML_MUSTINLINE Eurydice_arr_d4 libcrux_ml_dsa_simd_portable_vector_type_zero(void)
{
  return ((Eurydice_arr_d4){ { 0U } });
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline Eurydice_arr_d4 libcrux_ml_dsa_simd_portable_zero_65(void)
{
  return libcrux_ml_dsa_simd_portable_vector_type_zero();
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_vector_type_from_coefficient_array(
  Eurydice_dst_ref_shared_fc array,
  Eurydice_arr_d4 *out
)
{
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_a7(out),
    Eurydice_slice_subslice_shared_46(array,
      ((core_ops_range_Range_08){ (size_t)0U, LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT })),
    int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_from_coefficient_array_65(
  Eurydice_dst_ref_shared_fc array,
  Eurydice_arr_d4 *out
)
{
  libcrux_ml_dsa_simd_portable_vector_type_from_coefficient_array(array, out);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_vector_type_to_coefficient_array(
  const Eurydice_arr_d4 *value,
  Eurydice_dst_ref_mut_fc out
)
{
  Eurydice_slice_copy(out, Eurydice_array_to_slice_shared_a7(value), int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_to_coefficient_array_65(
  const Eurydice_arr_d4 *value,
  Eurydice_dst_ref_mut_fc out
)
{
  libcrux_ml_dsa_simd_portable_vector_type_to_coefficient_array(value, out);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_add(Eurydice_arr_d4 *lhs, const Eurydice_arr_d4 *rhs)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t uu____0 = i0;
    lhs->data[uu____0] = lhs->data[uu____0] + rhs->data[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_add_65(Eurydice_arr_d4 *lhs, const Eurydice_arr_d4 *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_add(lhs, rhs);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_subtract(
  Eurydice_arr_d4 *lhs,
  const Eurydice_arr_d4 *rhs
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    size_t uu____0 = i0;
    lhs->data[uu____0] = lhs->data[uu____0] - rhs->data[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_subtract_65(Eurydice_arr_d4 *lhs, const Eurydice_arr_d4 *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_subtract(lhs, rhs);
}

static KRML_MUSTINLINE bool
libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(
  const Eurydice_arr_d4 *simd_unit,
  int32_t bound
)
{
  bool result = false;
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    int32_t coefficient = simd_unit->data[i0];
    int32_t sign = coefficient >> 31U;
    int32_t normalized = coefficient - (sign & (int32_t)2 * coefficient);
    bool uu____0;
    if (result)
    {
      uu____0 = true;
    }
    else
    {
      uu____0 = normalized >= bound;
    }
    result = uu____0;
  }
  return result;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline bool
libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(
  const Eurydice_arr_d4 *simd_unit,
  int32_t bound
)
{
  return libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(simd_unit, bound);
}

typedef struct int32_t_x2_s
{
  int32_t fst;
  int32_t snd;
}
int32_t_x2;

static KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(int32_t gamma2, int32_t r)
{
  int32_t r0 = r + (r >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS);
  int32_t ceil_of_r_by_128 = (r0 + (int32_t)127) >> 7U;
  int32_t r1;
  switch (gamma2)
  {
    case 95232:
      {
        int32_t result = (ceil_of_r_by_128 * (int32_t)11275 + ((int32_t)1 << 23U)) >> 24U;
        int32_t result_0 = (result ^ ((int32_t)43 - result) >> 31U) & result;
        r1 = result_0;
        break;
      }
    case 261888:
      {
        int32_t result = (ceil_of_r_by_128 * (int32_t)1025 + ((int32_t)1 << 21U)) >> 22U;
        int32_t result_0 = result & (int32_t)15;
        r1 = result_0;
        break;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  int32_t alpha = gamma2 * (int32_t)2;
  int32_t r00 = r0 - r1 * alpha;
  r00 =
    r00 -
      (((LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS - (int32_t)1) / (int32_t)2 - r00) >> 31U &
        LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS);
  return ((int32_t_x2){ r00, r1 });
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_decompose(
  int32_t gamma2,
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_arr_d4 *low,
  Eurydice_arr_d4 *high
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    int32_t_x2
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2,
        simd_unit->data[i0]);
    int32_t uu____1 = uu____0.snd;
    low->data[i0] = uu____0.fst;
    high->data[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_decompose_65(
  int32_t gamma2,
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_arr_d4 *low,
  Eurydice_arr_d4 *high
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_decompose(gamma2, simd_unit, low, high);
}

static KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(
  int32_t low,
  int32_t high,
  int32_t gamma2
)
{
  int32_t uu____0;
  if (low > gamma2)
  {
    uu____0 = (int32_t)1;
  }
  else if (low < -gamma2)
  {
    uu____0 = (int32_t)1;
  }
  else if (low == -gamma2)
  {
    if (high != (int32_t)0)
    {
      uu____0 = (int32_t)1;
    }
    else
    {
      uu____0 = (int32_t)0;
    }
  }
  else
  {
    uu____0 = (int32_t)0;
  }
  return uu____0;
}

static KRML_MUSTINLINE size_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(
  const Eurydice_arr_d4 *low,
  const Eurydice_arr_d4 *high,
  int32_t gamma2,
  Eurydice_arr_d4 *hint
)
{
  size_t one_hints_count = (size_t)0U;
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    hint->data[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(low->data[i0],
        high->data[i0],
        gamma2);
    one_hints_count = one_hints_count + (size_t)hint->data[i0];
  }
  return one_hints_count;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline size_t
libcrux_ml_dsa_simd_portable_compute_hint_65(
  const Eurydice_arr_d4 *low,
  const Eurydice_arr_d4 *high,
  int32_t gamma2,
  Eurydice_arr_d4 *hint
)
{
  return libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(low, high, gamma2, hint);
}

static KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(int32_t gamma2, int32_t r, int32_t hint)
{
  int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2, r);
  int32_t r0 = uu____0.fst;
  int32_t r1 = uu____0.snd;
  int32_t uu____1;
  if (!(hint == (int32_t)0))
  {
    switch (gamma2)
    {
      case 95232:
        {
          if (r0 > (int32_t)0)
          {
            if (r1 == (int32_t)43)
            {
              uu____1 = (int32_t)0;
            }
            else
            {
              uu____1 = r1 + hint;
            }
          }
          else if (r1 == (int32_t)0)
          {
            uu____1 = (int32_t)43;
          }
          else
          {
            uu____1 = r1 - hint;
          }
          break;
        }
      case 261888:
        {
          if (r0 > (int32_t)0)
          {
            uu____1 = (r1 + hint) & (int32_t)15;
          }
          else
          {
            uu____1 = (r1 - hint) & (int32_t)15;
          }
          break;
        }
      default:
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
          KRML_HOST_EXIT(255U);
        }
    }
    return uu____1;
  }
  return r1;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_use_hint(
  int32_t gamma2,
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_arr_d4 *hint
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    int32_t
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(gamma2,
        simd_unit->data[i0],
        hint->data[i0]);
    hint->data[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_use_hint_65(
  int32_t gamma2,
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_arr_d4 *hint
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_use_hint(gamma2, simd_unit, hint);
}

static KRML_MUSTINLINE uint64_t
libcrux_ml_dsa_simd_portable_arithmetic_get_n_least_significant_bits(uint8_t n, uint64_t value)
{
  return value & ((1ULL << (uint32_t)n) - 1ULL);
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT (32U)

static KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element(int64_t value)
{
  uint64_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_get_n_least_significant_bits(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT,
      (uint64_t)value)
    * LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R;
  int32_t
  k =
    (int32_t)libcrux_ml_dsa_simd_portable_arithmetic_get_n_least_significant_bits(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT,
      t);
  int64_t k_times_modulus = (int64_t)k * (int64_t)LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS;
  int32_t
  c =
    (int32_t)(k_times_modulus >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  int32_t
  value_high =
    (int32_t)(value >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  return value_high - c;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(
  Eurydice_arr_d4 *lhs,
  const Eurydice_arr_d4 *rhs
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    lhs->data[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)lhs->data[i0] *
          (int64_t)rhs->data[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_montgomery_multiply_65(
  Eurydice_arr_d4 *lhs,
  const Eurydice_arr_d4 *rhs
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(lhs, rhs);
}

static KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_reduce_element(int32_t fe)
{
  int32_t quotient = (fe + ((int32_t)1 << 22U)) >> 23U;
  return fe - quotient * LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS;
}

static KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(int32_t t)
{
  int32_t t2 = t + (t >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS);
  int32_t
  t1 =
    (t2 - (int32_t)1 +
      ((int32_t)1 << (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T - (size_t)1U)))
    >> (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T;
  int32_t t0 = t2 - (t1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T);
  return ((int32_t_x2){ t0, t1 });
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_power2round(Eurydice_arr_d4 *t0, Eurydice_arr_d4 *t1)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(t0->data[i0]);
    int32_t uu____1 = uu____0.snd;
    t0->data[i0] = uu____0.fst;
    t1->data[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_power2round_65(Eurydice_arr_d4 *t0, Eurydice_arr_d4 *t1)
{
  libcrux_ml_dsa_simd_portable_arithmetic_power2round(t0, t1);
}

static KRML_MUSTINLINE size_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_field_modulus(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_fc out
)
{
  size_t sampled = (size_t)0U;
  for (size_t i = (size_t)0U; i < randomness.meta / (size_t)3U; i++)
  {
    size_t i0 = i;
    int32_t b0 = (int32_t)randomness.ptr[i0 * (size_t)3U];
    int32_t b1 = (int32_t)randomness.ptr[i0 * (size_t)3U + (size_t)1U];
    int32_t b2 = (int32_t)randomness.ptr[i0 * (size_t)3U + (size_t)2U];
    int32_t coefficient = ((b2 << 16U | b1 << 8U) | b0) & (int32_t)8388607;
    if (coefficient < LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS)
    {
      out.ptr[sampled] = coefficient;
      sampled++;
    }
  }
  return sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline size_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_field_modulus_65(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_fc out
)
{
  return
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_field_modulus(randomness,
      out);
}

static KRML_MUSTINLINE size_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_fc out
)
{
  size_t sampled = (size_t)0U;
  for (size_t i = (size_t)0U; i < randomness.meta; i++)
  {
    size_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    if (try_0 < 15U)
    {
      int32_t try_00 = (int32_t)try_0;
      int32_t try_0_mod_5 = try_00 - (try_00 * (int32_t)26 >> 7U) * (int32_t)5;
      out.ptr[sampled] = (int32_t)2 - try_0_mod_5;
      sampled++;
    }
    if (try_1 < 15U)
    {
      int32_t try_10 = (int32_t)try_1;
      int32_t try_1_mod_5 = try_10 - (try_10 * (int32_t)26 >> 7U) * (int32_t)5;
      out.ptr[sampled] = (int32_t)2 - try_1_mod_5;
      sampled++;
    }
  }
  return sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline size_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_fc out
)
{
  return
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(randomness,
      out);
}

static KRML_MUSTINLINE size_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_fc out
)
{
  size_t sampled = (size_t)0U;
  for (size_t i = (size_t)0U; i < randomness.meta; i++)
  {
    size_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    if (try_0 < 9U)
    {
      out.ptr[sampled] = (int32_t)4 - (int32_t)try_0;
      sampled++;
    }
    if (try_1 < 9U)
    {
      out.ptr[sampled] = (int32_t)4 - (int32_t)try_1;
      sampled++;
    }
  }
  return sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline size_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_fc out
)
{
  return
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(randomness,
      out);
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)1 << 19U)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U / (size_t)2U; i++)
  {
    size_t i0 = i;
    Eurydice_dst_ref_shared_fc
    coefficients =
      Eurydice_array_to_subslice_shared_7f(simd_unit,
        ((core_ops_range_Range_08){ i0 * (size_t)2U, i0 * (size_t)2U + (size_t)2U }));
    int32_t
    coefficient0 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficients.ptr[0U];
    int32_t
    coefficient1 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficients.ptr[1U];
    serialized.ptr[(size_t)5U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(size_t)5U * i0 + (size_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(size_t)5U * i0 + (size_t)2U] = (uint8_t)(coefficient0 >> 16U);
    size_t uu____0 = (size_t)5U * i0 + (size_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(coefficient1 << 4U);
    serialized.ptr[(size_t)5U * i0 + (size_t)3U] = (uint8_t)(coefficient1 >> 4U);
    serialized.ptr[(size_t)5U * i0 + (size_t)4U] = (uint8_t)(coefficient1 >> 12U);
  }
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)1 << 17U)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U / (size_t)4U; i++)
  {
    size_t i0 = i;
    Eurydice_dst_ref_shared_fc
    coefficients =
      Eurydice_array_to_subslice_shared_7f(simd_unit,
        ((core_ops_range_Range_08){ i0 * (size_t)4U, i0 * (size_t)4U + (size_t)4U }));
    int32_t
    coefficient0 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[0U];
    int32_t
    coefficient1 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[1U];
    int32_t
    coefficient2 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[2U];
    int32_t
    coefficient3 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[3U];
    serialized.ptr[(size_t)9U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(size_t)9U * i0 + (size_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(size_t)9U * i0 + (size_t)2U] = (uint8_t)(coefficient0 >> 16U);
    size_t uu____0 = (size_t)9U * i0 + (size_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(coefficient1 << 2U);
    serialized.ptr[(size_t)9U * i0 + (size_t)3U] = (uint8_t)(coefficient1 >> 6U);
    serialized.ptr[(size_t)9U * i0 + (size_t)4U] = (uint8_t)(coefficient1 >> 14U);
    size_t uu____1 = (size_t)9U * i0 + (size_t)4U;
    serialized.ptr[uu____1] =
      (uint32_t)serialized.ptr[uu____1] | (uint32_t)(uint8_t)(coefficient2 << 4U);
    serialized.ptr[(size_t)9U * i0 + (size_t)5U] = (uint8_t)(coefficient2 >> 4U);
    serialized.ptr[(size_t)9U * i0 + (size_t)6U] = (uint8_t)(coefficient2 >> 12U);
    size_t uu____2 = (size_t)9U * i0 + (size_t)6U;
    serialized.ptr[uu____2] =
      (uint32_t)serialized.ptr[uu____2] | (uint32_t)(uint8_t)(coefficient3 << 6U);
    serialized.ptr[(size_t)9U * i0 + (size_t)7U] = (uint8_t)(coefficient3 >> 2U);
    serialized.ptr[(size_t)9U * i0 + (size_t)8U] = (uint8_t)(coefficient3 >> 10U);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized,
  size_t gamma1_exponent
)
{
  switch (gamma1_exponent)
  {
    case 17U:
      {
        break;
      }
    case 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(simd_unit,
          serialized);
        return;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(simd_unit,
    serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_gamma1_serialize_65(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized,
  size_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(simd_unit, serialized, gamma1_exponent);
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)1 << 19U)

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK ((LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 << 1U) - (int32_t)1)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *simd_unit
)
{
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)5U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)5U, i0 * (size_t)5U + (size_t)5U }));
    int32_t coefficient0 = (int32_t)bytes.ptr[0U];
    coefficient0 = coefficient0 | (int32_t)bytes.ptr[1U] << 8U;
    coefficient0 = coefficient0 | (int32_t)bytes.ptr[2U] << 16U;
    coefficient0 =
      coefficient0 &
        LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)bytes.ptr[2U] >> 4U;
    coefficient1 = coefficient1 | (int32_t)bytes.ptr[3U] << 4U;
    coefficient1 = coefficient1 | (int32_t)bytes.ptr[4U] << 12U;
    simd_unit->data[(size_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient0;
    simd_unit->data[(size_t)2U * i0 + (size_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient1;
  }
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)1 << 17U)

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK ((LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 << 1U) - (int32_t)1)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *simd_unit
)
{
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)9U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)9U, i0 * (size_t)9U + (size_t)9U }));
    int32_t coefficient0 = (int32_t)bytes.ptr[0U];
    coefficient0 = coefficient0 | (int32_t)bytes.ptr[1U] << 8U;
    coefficient0 = coefficient0 | (int32_t)bytes.ptr[2U] << 16U;
    coefficient0 =
      coefficient0 &
        LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)bytes.ptr[2U] >> 2U;
    coefficient1 = coefficient1 | (int32_t)bytes.ptr[3U] << 6U;
    coefficient1 = coefficient1 | (int32_t)bytes.ptr[4U] << 14U;
    coefficient1 =
      coefficient1 &
        LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient2 = (int32_t)bytes.ptr[4U] >> 4U;
    coefficient2 = coefficient2 | (int32_t)bytes.ptr[5U] << 4U;
    coefficient2 = coefficient2 | (int32_t)bytes.ptr[6U] << 12U;
    coefficient2 =
      coefficient2 &
        LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient3 = (int32_t)bytes.ptr[6U] >> 6U;
    coefficient3 = coefficient3 | (int32_t)bytes.ptr[7U] << 2U;
    coefficient3 = coefficient3 | (int32_t)bytes.ptr[8U] << 10U;
    coefficient3 =
      coefficient3 &
        LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    simd_unit->data[(size_t)4U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient0;
    simd_unit->data[(size_t)4U * i0 + (size_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient1;
    simd_unit->data[(size_t)4U * i0 + (size_t)2U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient2;
    simd_unit->data[(size_t)4U * i0 + (size_t)3U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient3;
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *out,
  size_t gamma1_exponent
)
{
  switch (gamma1_exponent)
  {
    case 17U:
      {
        break;
      }
    case 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(serialized,
          out);
        return;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(serialized,
    out);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *out,
  size_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(serialized, out, gamma1_exponent);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->data[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->data[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->data[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->data[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->data[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->data[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->data[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->data[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient3 << 4U | (uint32_t)coefficient2;
  uint8_t byte2 = (uint32_t)coefficient5 << 4U | (uint32_t)coefficient4;
  uint8_t byte3 = (uint32_t)coefficient7 << 4U | (uint32_t)coefficient6;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->data[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->data[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->data[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->data[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->data[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->data[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->data[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->data[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 6U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient2 << 4U | (uint32_t)coefficient1 >> 2U;
  uint8_t byte2 = (uint32_t)coefficient3 << 2U | (uint32_t)coefficient2 >> 4U;
  uint8_t byte3 = (uint32_t)coefficient5 << 6U | (uint32_t)coefficient4;
  uint8_t byte4 = (uint32_t)coefficient6 << 4U | (uint32_t)coefficient5 >> 2U;
  uint8_t byte5 = (uint32_t)coefficient7 << 2U | (uint32_t)coefficient6 >> 4U;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
  serialized.ptr[4U] = byte4;
  serialized.ptr[5U] = byte5;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  switch ((uint8_t)serialized.meta)
  {
    case 4U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(simd_unit, serialized);
        break;
      }
    case 6U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(simd_unit, serialized);
        break;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_commitment_serialize_65(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(simd_unit, serialized);
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA ((int32_t)4)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U / (size_t)2U; i++)
  {
    size_t i0 = i;
    Eurydice_dst_ref_shared_fc
    coefficients =
      Eurydice_array_to_subslice_shared_7f(simd_unit,
        ((core_ops_range_Range_08){ i0 * (size_t)2U, i0 * (size_t)2U + (size_t)2U }));
    uint8_t
    coefficient0 =
      (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA -
        coefficients.ptr[0U]);
    uint8_t
    coefficient1 =
      (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA -
        coefficients.ptr[1U]);
    serialized.ptr[i0] = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  }
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA ((int32_t)2)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  uint8_t
  coefficient0 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[0U]);
  uint8_t
  coefficient1 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[1U]);
  uint8_t
  coefficient2 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[2U]);
  uint8_t
  coefficient3 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[3U]);
  uint8_t
  coefficient4 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[4U]);
  uint8_t
  coefficient5 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[5U]);
  uint8_t
  coefficient6 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[6U]);
  uint8_t
  coefficient7 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->data[7U]);
  serialized.ptr[0U] =
    ((uint32_t)coefficient2 << 6U | (uint32_t)coefficient1 << 3U) | (uint32_t)coefficient0;
  serialized.ptr[1U] =
    (((uint32_t)coefficient5 << 7U | (uint32_t)coefficient4 << 4U) | (uint32_t)coefficient3 << 1U)
    | (uint32_t)coefficient2 >> 2U;
  serialized.ptr[2U] =
    ((uint32_t)coefficient7 << 5U | (uint32_t)coefficient6 << 2U) | (uint32_t)coefficient5 >> 1U;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_error_serialize(
  libcrux_ml_dsa_constants_Eta eta,
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  switch (eta)
  {
    case libcrux_ml_dsa_constants_Eta_Two:
      {
        break;
      }
    case libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(simd_unit, serialized);
        return;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(simd_unit, serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_error_serialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_serialize(eta, simd_unit, serialized);
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA ((int32_t)4)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *simd_units
)
{
  for (size_t i = (size_t)0U; i < serialized.meta; i++)
  {
    size_t i0 = i;
    const uint8_t *byte = &serialized.ptr[i0];
    uint8_t uu____0 = core_ops_bit__core__ops__bit__BitAnd_u8__u8__for__0__u8___bitand(byte, 15U);
    simd_units->data[(size_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA - (int32_t)uu____0;
    uint8_t
    uu____1 = core_ops_bit__core__ops__bit__Shr_i32__u8__for__0__u8___shr(byte, (int32_t)4);
    simd_units->data[(size_t)2U * i0 + (size_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA - (int32_t)uu____1;
  }
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA ((int32_t)2)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *simd_unit
)
{
  int32_t byte0 = (int32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)serialized.ptr[2U];
  simd_unit->data[0U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      (byte0 & (int32_t)7);
  simd_unit->data[1U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      (byte0 >> 3U & (int32_t)7);
  simd_unit->data[2U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte0 >> 6U | byte1 << 2U) & (int32_t)7);
  simd_unit->data[3U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      (byte1 >> 1U & (int32_t)7);
  simd_unit->data[4U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      (byte1 >> 4U & (int32_t)7);
  simd_unit->data[5U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte1 >> 7U | byte2 << 1U) & (int32_t)7);
  simd_unit->data[6U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      (byte2 >> 2U & (int32_t)7);
  simd_unit->data[7U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      (byte2 >> 5U & (int32_t)7);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_error_deserialize(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *out
)
{
  switch (eta)
  {
    case libcrux_ml_dsa_constants_Eta_Two:
      {
        break;
      }
    case libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(serialized, out);
        return;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(serialized, out);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_error_deserialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *out
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize(eta, serialized, out);
}

static KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(int32_t t0)
{
  return
    ((int32_t)1 << (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T - (size_t)1U)) - t0;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_t0_serialize(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  int32_t
  coefficient0 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[0U]);
  int32_t
  coefficient1 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[1U]);
  int32_t
  coefficient2 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[2U]);
  int32_t
  coefficient3 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[3U]);
  int32_t
  coefficient4 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[4U]);
  int32_t
  coefficient5 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[5U]);
  int32_t
  coefficient6 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[6U]);
  int32_t
  coefficient7 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->data[7U]);
  serialized.ptr[0U] = (uint8_t)coefficient0;
  serialized.ptr[1U] =
    (uint32_t)(uint8_t)(coefficient0 >> 8U) | (uint32_t)(uint8_t)(coefficient1 << 5U);
  serialized.ptr[2U] = (uint8_t)(coefficient1 >> 3U);
  serialized.ptr[3U] =
    (uint32_t)(uint8_t)(coefficient1 >> 11U) | (uint32_t)(uint8_t)(coefficient2 << 2U);
  serialized.ptr[4U] =
    (uint32_t)(uint8_t)(coefficient2 >> 6U) | (uint32_t)(uint8_t)(coefficient3 << 7U);
  serialized.ptr[5U] = (uint8_t)(coefficient3 >> 1U);
  serialized.ptr[6U] =
    (uint32_t)(uint8_t)(coefficient3 >> 9U) | (uint32_t)(uint8_t)(coefficient4 << 4U);
  serialized.ptr[7U] = (uint8_t)(coefficient4 >> 4U);
  serialized.ptr[8U] =
    (uint32_t)(uint8_t)(coefficient4 >> 12U) | (uint32_t)(uint8_t)(coefficient5 << 1U);
  serialized.ptr[9U] =
    (uint32_t)(uint8_t)(coefficient5 >> 7U) | (uint32_t)(uint8_t)(coefficient6 << 6U);
  serialized.ptr[10U] = (uint8_t)(coefficient6 >> 2U);
  serialized.ptr[11U] =
    (uint32_t)(uint8_t)(coefficient6 >> 10U) | (uint32_t)(uint8_t)(coefficient7 << 3U);
  serialized.ptr[12U] = (uint8_t)(coefficient7 >> 5U);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_t0_serialize_65(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_serialize(simd_unit, out);
}

#define LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK (((int32_t)1 << (uint32_t)(int32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T) - (int32_t)1)

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *simd_unit
)
{
  int32_t byte0 = (int32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)serialized.ptr[2U];
  int32_t byte3 = (int32_t)serialized.ptr[3U];
  int32_t byte4 = (int32_t)serialized.ptr[4U];
  int32_t byte5 = (int32_t)serialized.ptr[5U];
  int32_t byte6 = (int32_t)serialized.ptr[6U];
  int32_t byte7 = (int32_t)serialized.ptr[7U];
  int32_t byte8 = (int32_t)serialized.ptr[8U];
  int32_t byte9 = (int32_t)serialized.ptr[9U];
  int32_t byte10 = (int32_t)serialized.ptr[10U];
  int32_t byte11 = (int32_t)serialized.ptr[11U];
  int32_t byte12 = (int32_t)serialized.ptr[12U];
  int32_t coefficient0 = byte0;
  coefficient0 = coefficient0 | byte1 << 8U;
  coefficient0 =
    coefficient0 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient1 = byte1 >> 5U;
  coefficient1 = coefficient1 | byte2 << 3U;
  coefficient1 = coefficient1 | byte3 << 11U;
  coefficient1 =
    coefficient1 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient2 = byte3 >> 2U;
  coefficient2 = coefficient2 | byte4 << 6U;
  coefficient2 =
    coefficient2 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient3 = byte4 >> 7U;
  coefficient3 = coefficient3 | byte5 << 1U;
  coefficient3 = coefficient3 | byte6 << 9U;
  coefficient3 =
    coefficient3 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient4 = byte6 >> 4U;
  coefficient4 = coefficient4 | byte7 << 4U;
  coefficient4 = coefficient4 | byte8 << 12U;
  coefficient4 =
    coefficient4 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient5 = byte8 >> 1U;
  coefficient5 = coefficient5 | byte9 << 7U;
  coefficient5 =
    coefficient5 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient6 = byte9 >> 6U;
  coefficient6 = coefficient6 | byte10 << 2U;
  coefficient6 = coefficient6 | byte11 << 10U;
  coefficient6 =
    coefficient6 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient7 = byte11 >> 3U;
  coefficient7 = coefficient7 | byte12 << 5U;
  coefficient7 =
    coefficient7 &
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  simd_unit->data[0U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient0);
  simd_unit->data[1U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient1);
  simd_unit->data[2U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient2);
  simd_unit->data[3U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient3);
  simd_unit->data[4U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient4);
  simd_unit->data[5U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient5);
  simd_unit->data[6U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient6);
  simd_unit->data[7U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient7);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_t0_deserialize_65(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(serialized, out);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_t1_serialize(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U / (size_t)4U; i++)
  {
    size_t i0 = i;
    Eurydice_dst_ref_shared_fc
    coefficients =
      Eurydice_array_to_subslice_shared_7f(simd_unit,
        ((core_ops_range_Range_08){ i0 * (size_t)4U, i0 * (size_t)4U + (size_t)4U }));
    serialized.ptr[(size_t)5U * i0] = (uint8_t)(coefficients.ptr[0U] & (int32_t)255);
    serialized.ptr[(size_t)5U * i0 + (size_t)1U] =
      (uint32_t)(uint8_t)(coefficients.ptr[1U] & (int32_t)63) << 2U |
        (uint32_t)(uint8_t)(coefficients.ptr[0U] >> 8U & (int32_t)3);
    serialized.ptr[(size_t)5U * i0 + (size_t)2U] =
      (uint32_t)(uint8_t)(coefficients.ptr[2U] & (int32_t)15) << 4U |
        (uint32_t)(uint8_t)(coefficients.ptr[1U] >> 6U & (int32_t)15);
    serialized.ptr[(size_t)5U * i0 + (size_t)3U] =
      (uint32_t)(uint8_t)(coefficients.ptr[3U] & (int32_t)3) << 6U |
        (uint32_t)(uint8_t)(coefficients.ptr[2U] >> 4U & (int32_t)63);
    serialized.ptr[(size_t)5U * i0 + (size_t)4U] =
      (uint8_t)(coefficients.ptr[3U] >> 2U & (int32_t)255);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_t1_serialize_65(
  const Eurydice_arr_d4 *simd_unit,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_serialize(simd_unit, out);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *simd_unit
)
{
  int32_t
  mask = ((int32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_UPPER_PART_OF_T) - (int32_t)1;
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)5U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)5U, i0 * (size_t)5U + (size_t)5U }));
    int32_t byte0 = (int32_t)bytes.ptr[0U];
    int32_t byte1 = (int32_t)bytes.ptr[1U];
    int32_t byte2 = (int32_t)bytes.ptr[2U];
    int32_t byte3 = (int32_t)bytes.ptr[3U];
    int32_t byte4 = (int32_t)bytes.ptr[4U];
    simd_unit->data[(size_t)4U * i0] = (byte0 | byte1 << 8U) & mask;
    simd_unit->data[(size_t)4U * i0 + (size_t)1U] = (byte1 >> 2U | byte2 << 6U) & mask;
    simd_unit->data[(size_t)4U * i0 + (size_t)2U] = (byte2 >> 4U | byte3 << 4U) & mask;
    simd_unit->data[(size_t)4U * i0 + (size_t)3U] = (byte3 >> 6U | byte4 << 2U) & mask;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_t1_deserialize_65(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_d4 *out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(serialized, out);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_d4 *simd_unit,
  int32_t c
)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    simd_unit->data[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)simd_unit->data[i0]
        * (int64_t)c);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- $32size_t
*/
typedef struct Eurydice_arr_a4_s { Eurydice_arr_d4 data[32U]; } Eurydice_arr_a4;

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(
  Eurydice_arr_a4 *re,
  size_t index,
  size_t step_by,
  int32_t zeta
)
{
  Eurydice_arr_d4 tmp = re->data[index + step_by];
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&tmp, zeta);
  re->data[index + step_by] = re->data[index];
  libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[index + step_by], &tmp);
  libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[index], &tmp);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_99(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)16U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)16U, (int32_t)25847);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_7(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_99(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 8
- ZETA= -2608894
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_990(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)8U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)8U, (int32_t)-2608894);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -518909
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)8U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)8U, (int32_t)-518909);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_6(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_990(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 4
- ZETA= 237124
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_991(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)4U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)4U, (int32_t)237124);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -777960
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a8(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)8U; i < (size_t)8U + (size_t)4U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)4U, (int32_t)-777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -876248
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)4U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)4U, (int32_t)-876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 466468
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d9(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)24U; i < (size_t)24U + (size_t)4U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)4U, (int32_t)466468);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_5(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_991(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a8(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d9(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 2
- ZETA= 1826347
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_992(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)1826347);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 2353451
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_6b(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)4U; i < (size_t)4U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -359251
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a80(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)8U; i < (size_t)8U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)-359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= -2091905
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_95(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)12U; i < (size_t)12U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)-2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= 3119733
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a1(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -2884855
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_de(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)20U; i < (size_t)20U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)-2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 3111497
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d90(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)24U; i < (size_t)24U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 2680103
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3b(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)28U; i < (size_t)28U + (size_t)2U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)2U, (int32_t)2680103);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_4(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_992(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_6b(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a80(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_95(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a1(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_de(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d90(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3b(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 2725464
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_993(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)2725464);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 1024112
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1c(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)2U; i < (size_t)2U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -1079900
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_6b0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)4U; i < (size_t)4U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 3585928
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_44(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)6U; i < (size_t)6U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -549488
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a81(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)8U; i < (size_t)8U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1119584
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1f(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)10U; i < (size_t)10U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= 2619752
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_950(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)12U; i < (size_t)12U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2108549
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3b0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)14U; i < (size_t)14U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2118186
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a2(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= -3859737
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_e4(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)18U; i < (size_t)18U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1399561
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_de0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)20U; i < (size_t)20U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -3277672
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_05(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)22U; i < (size_t)22U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 1757237
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d91(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)24U; i < (size_t)24U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -19422
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3a(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)26U; i < (size_t)26U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)-19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 4010497
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3b1(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)28U; i < (size_t)28U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 280005
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)30U; i < (size_t)30U + (size_t)1U; i++)
  {
    size_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (size_t)1U, (int32_t)280005);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_3(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_993(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1c(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_6b0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_44(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a81(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1f(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_950(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3b0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_7a2(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_e4(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_de0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_05(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d91(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3a(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_3b1(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_a0(re);
}

static KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(int32_t fe, int32_t fer)
{
  return
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)fe * (int64_t)fer);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta,
  size_t index,
  size_t step
)
{
  int32_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(simd_unit->data[index +
        step],
      zeta);
  simd_unit->data[index + step] = simd_unit->data[index] - t;
  simd_unit->data[index] = simd_unit->data[index] + t;
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (size_t)0U, (size_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (size_t)1U, (size_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (size_t)2U, (size_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (size_t)3U, (size_t)4U);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(
  Eurydice_arr_a4 *re,
  size_t index,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(&re->data[index], zeta);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)0U, (int32_t)2706023);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)1U, (int32_t)95776);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)2U, (int32_t)3077325);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)3U, (int32_t)3530437);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)4U, (int32_t)-1661693);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)5U, (int32_t)-3592148);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)6U, (int32_t)-2537516);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)7U, (int32_t)3915439);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)8U, (int32_t)-3861115);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)9U, (int32_t)-3043716);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)10U, (int32_t)3574422);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)11U, (int32_t)-2867647);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)12U, (int32_t)3539968);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)13U, (int32_t)-300467);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)14U, (int32_t)2348700);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)15U, (int32_t)-539299);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)16U, (int32_t)-1699267);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)17U, (int32_t)-1643818);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)18U, (int32_t)3505694);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)19U, (int32_t)-3821735);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)20U, (int32_t)3507263);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)21U, (int32_t)-2140649);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)22U, (int32_t)-1600420);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)23U, (int32_t)3699596);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)24U, (int32_t)811944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)25U, (int32_t)531354);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)26U, (int32_t)954230);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)27U, (int32_t)3881043);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)28U, (int32_t)3900724);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)29U, (int32_t)-2556880);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)30U, (int32_t)2071892);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (size_t)31U, (int32_t)-2797779);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta1,
  int32_t zeta2
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta1, (size_t)0U, (size_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta1, (size_t)1U, (size_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta2, (size_t)4U, (size_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta2, (size_t)5U, (size_t)2U);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(
  Eurydice_arr_a4 *re,
  size_t index,
  int32_t zeta_0,
  int32_t zeta_1
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(&re->data[index], zeta_0, zeta_1);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)0U,
    (int32_t)-3930395,
    (int32_t)-1528703);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)1U,
    (int32_t)-3677745,
    (int32_t)-3041255);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)2U,
    (int32_t)-1452451,
    (int32_t)3475950);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)3U,
    (int32_t)2176455,
    (int32_t)-1585221);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)4U,
    (int32_t)-1257611,
    (int32_t)1939314);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)5U,
    (int32_t)-4083598,
    (int32_t)-1000202);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)6U,
    (int32_t)-3190144,
    (int32_t)-3157330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)7U,
    (int32_t)-3632928,
    (int32_t)126922);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)8U,
    (int32_t)3412210,
    (int32_t)-983419);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)9U,
    (int32_t)2147896,
    (int32_t)2715295);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)10U,
    (int32_t)-2967645,
    (int32_t)-3693493);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)11U,
    (int32_t)-411027,
    (int32_t)-2477047);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)12U,
    (int32_t)-671102,
    (int32_t)-1228525);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)13U,
    (int32_t)-22981,
    (int32_t)-1308169);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)14U,
    (int32_t)-381987,
    (int32_t)1349076);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)15U,
    (int32_t)1852771,
    (int32_t)-1430430);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)16U,
    (int32_t)-3343383,
    (int32_t)264944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)17U,
    (int32_t)508951,
    (int32_t)3097992);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)18U,
    (int32_t)44288,
    (int32_t)-1100098);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)19U,
    (int32_t)904516,
    (int32_t)3958618);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)20U,
    (int32_t)-3724342,
    (int32_t)-8578);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)21U,
    (int32_t)1653064,
    (int32_t)-3249728);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)22U,
    (int32_t)2389356,
    (int32_t)-210977);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)23U,
    (int32_t)759969,
    (int32_t)-1316856);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)24U,
    (int32_t)189548,
    (int32_t)-3553272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)25U,
    (int32_t)3159746,
    (int32_t)-1851402);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)26U,
    (int32_t)-2409325,
    (int32_t)-177440);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)27U,
    (int32_t)1315589,
    (int32_t)1341330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)28U,
    (int32_t)1285669,
    (int32_t)-1584928);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)29U,
    (int32_t)-812732,
    (int32_t)-1439742);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)30U,
    (int32_t)-3019102,
    (int32_t)-3881060);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re,
    (size_t)31U,
    (int32_t)-3628969,
    (int32_t)3839961);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta0, (size_t)0U, (size_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta1, (size_t)2U, (size_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta2, (size_t)4U, (size_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta3, (size_t)6U, (size_t)1U);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(
  Eurydice_arr_a4 *re,
  size_t index,
  int32_t zeta_0,
  int32_t zeta_1,
  int32_t zeta_2,
  int32_t zeta_3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(&re->data[index],
    zeta_0,
    zeta_1,
    zeta_2,
    zeta_3);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)0U,
    (int32_t)2091667,
    (int32_t)3407706,
    (int32_t)2316500,
    (int32_t)3817976);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)1U,
    (int32_t)-3342478,
    (int32_t)2244091,
    (int32_t)-2446433,
    (int32_t)-3562462);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)2U,
    (int32_t)266997,
    (int32_t)2434439,
    (int32_t)-1235728,
    (int32_t)3513181);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)3U,
    (int32_t)-3520352,
    (int32_t)-3759364,
    (int32_t)-1197226,
    (int32_t)-3193378);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)4U,
    (int32_t)900702,
    (int32_t)1859098,
    (int32_t)909542,
    (int32_t)819034);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)5U,
    (int32_t)495491,
    (int32_t)-1613174,
    (int32_t)-43260,
    (int32_t)-522500);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)6U,
    (int32_t)-655327,
    (int32_t)-3122442,
    (int32_t)2031748,
    (int32_t)3207046);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)7U,
    (int32_t)-3556995,
    (int32_t)-525098,
    (int32_t)-768622,
    (int32_t)-3595838);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)8U,
    (int32_t)342297,
    (int32_t)286988,
    (int32_t)-2437823,
    (int32_t)4108315);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)9U,
    (int32_t)3437287,
    (int32_t)-3342277,
    (int32_t)1735879,
    (int32_t)203044);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)10U,
    (int32_t)2842341,
    (int32_t)2691481,
    (int32_t)-2590150,
    (int32_t)1265009);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)11U,
    (int32_t)4055324,
    (int32_t)1247620,
    (int32_t)2486353,
    (int32_t)1595974);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)12U,
    (int32_t)-3767016,
    (int32_t)1250494,
    (int32_t)2635921,
    (int32_t)-3548272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)13U,
    (int32_t)-2994039,
    (int32_t)1869119,
    (int32_t)1903435,
    (int32_t)-1050970);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)14U,
    (int32_t)-1333058,
    (int32_t)1237275,
    (int32_t)-3318210,
    (int32_t)-1430225);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)15U,
    (int32_t)-451100,
    (int32_t)1312455,
    (int32_t)3306115,
    (int32_t)-1962642);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)16U,
    (int32_t)-1279661,
    (int32_t)1917081,
    (int32_t)-2546312,
    (int32_t)-1374803);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)17U,
    (int32_t)1500165,
    (int32_t)777191,
    (int32_t)2235880,
    (int32_t)3406031);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)18U,
    (int32_t)-542412,
    (int32_t)-2831860,
    (int32_t)-1671176,
    (int32_t)-1846953);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)19U,
    (int32_t)-2584293,
    (int32_t)-3724270,
    (int32_t)594136,
    (int32_t)-3776993);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)20U,
    (int32_t)-2013608,
    (int32_t)2432395,
    (int32_t)2454455,
    (int32_t)-164721);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)21U,
    (int32_t)1957272,
    (int32_t)3369112,
    (int32_t)185531,
    (int32_t)-1207385);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)22U,
    (int32_t)-3183426,
    (int32_t)162844,
    (int32_t)1616392,
    (int32_t)3014001);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)23U,
    (int32_t)810149,
    (int32_t)1652634,
    (int32_t)-3694233,
    (int32_t)-1799107);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)24U,
    (int32_t)-3038916,
    (int32_t)3523897,
    (int32_t)3866901,
    (int32_t)269760);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)25U,
    (int32_t)2213111,
    (int32_t)-975884,
    (int32_t)1717735,
    (int32_t)472078);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)26U,
    (int32_t)-426683,
    (int32_t)1723600,
    (int32_t)-1803090,
    (int32_t)1910376);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)27U,
    (int32_t)-1667432,
    (int32_t)-1104333,
    (int32_t)-260646,
    (int32_t)-3833893);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)28U,
    (int32_t)-2939036,
    (int32_t)-2235985,
    (int32_t)-420899,
    (int32_t)-2286327);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)29U,
    (int32_t)183443,
    (int32_t)-976891,
    (int32_t)1612842,
    (int32_t)-3545687);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)30U,
    (int32_t)-554416,
    (int32_t)3919660,
    (int32_t)-48306,
    (int32_t)-1362209);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (size_t)31U,
    (int32_t)3937738,
    (int32_t)1400424,
    (int32_t)-846154,
    (int32_t)1976782);
}

static KRML_MUSTINLINE void libcrux_ml_dsa_simd_portable_ntt_ntt(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_7(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_6(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_5(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_4(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_3(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(re);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void libcrux_ml_dsa_simd_portable_ntt_65(Eurydice_arr_a4 *simd_units)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt(simd_units);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta,
  size_t index,
  size_t step
)
{
  int32_t a_minus_b = simd_unit->data[index + step] - simd_unit->data[index];
  simd_unit->data[index] = simd_unit->data[index] + simd_unit->data[index + step];
  simd_unit->data[index + step] =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      zeta);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta0,
    (size_t)0U,
    (size_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta1,
    (size_t)2U,
    (size_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta2,
    (size_t)4U,
    (size_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta3,
    (size_t)6U,
    (size_t)1U);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(
  Eurydice_arr_a4 *re,
  size_t index,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(&re->data[index],
    zeta0,
    zeta1,
    zeta2,
    zeta3);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)0U,
    (int32_t)1976782,
    (int32_t)-846154,
    (int32_t)1400424,
    (int32_t)3937738);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)1U,
    (int32_t)-1362209,
    (int32_t)-48306,
    (int32_t)3919660,
    (int32_t)-554416);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)2U,
    (int32_t)-3545687,
    (int32_t)1612842,
    (int32_t)-976891,
    (int32_t)183443);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)3U,
    (int32_t)-2286327,
    (int32_t)-420899,
    (int32_t)-2235985,
    (int32_t)-2939036);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)4U,
    (int32_t)-3833893,
    (int32_t)-260646,
    (int32_t)-1104333,
    (int32_t)-1667432);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)5U,
    (int32_t)1910376,
    (int32_t)-1803090,
    (int32_t)1723600,
    (int32_t)-426683);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)6U,
    (int32_t)472078,
    (int32_t)1717735,
    (int32_t)-975884,
    (int32_t)2213111);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)7U,
    (int32_t)269760,
    (int32_t)3866901,
    (int32_t)3523897,
    (int32_t)-3038916);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)8U,
    (int32_t)-1799107,
    (int32_t)-3694233,
    (int32_t)1652634,
    (int32_t)810149);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)9U,
    (int32_t)3014001,
    (int32_t)1616392,
    (int32_t)162844,
    (int32_t)-3183426);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)10U,
    (int32_t)-1207385,
    (int32_t)185531,
    (int32_t)3369112,
    (int32_t)1957272);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)11U,
    (int32_t)-164721,
    (int32_t)2454455,
    (int32_t)2432395,
    (int32_t)-2013608);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)12U,
    (int32_t)-3776993,
    (int32_t)594136,
    (int32_t)-3724270,
    (int32_t)-2584293);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)13U,
    (int32_t)-1846953,
    (int32_t)-1671176,
    (int32_t)-2831860,
    (int32_t)-542412);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)14U,
    (int32_t)3406031,
    (int32_t)2235880,
    (int32_t)777191,
    (int32_t)1500165);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)15U,
    (int32_t)-1374803,
    (int32_t)-2546312,
    (int32_t)1917081,
    (int32_t)-1279661);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)16U,
    (int32_t)-1962642,
    (int32_t)3306115,
    (int32_t)1312455,
    (int32_t)-451100);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)17U,
    (int32_t)-1430225,
    (int32_t)-3318210,
    (int32_t)1237275,
    (int32_t)-1333058);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)18U,
    (int32_t)-1050970,
    (int32_t)1903435,
    (int32_t)1869119,
    (int32_t)-2994039);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)19U,
    (int32_t)-3548272,
    (int32_t)2635921,
    (int32_t)1250494,
    (int32_t)-3767016);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)20U,
    (int32_t)1595974,
    (int32_t)2486353,
    (int32_t)1247620,
    (int32_t)4055324);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)21U,
    (int32_t)1265009,
    (int32_t)-2590150,
    (int32_t)2691481,
    (int32_t)2842341);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)22U,
    (int32_t)203044,
    (int32_t)1735879,
    (int32_t)-3342277,
    (int32_t)3437287);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)23U,
    (int32_t)4108315,
    (int32_t)-2437823,
    (int32_t)286988,
    (int32_t)342297);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)24U,
    (int32_t)-3595838,
    (int32_t)-768622,
    (int32_t)-525098,
    (int32_t)-3556995);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)25U,
    (int32_t)3207046,
    (int32_t)2031748,
    (int32_t)-3122442,
    (int32_t)-655327);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)26U,
    (int32_t)-522500,
    (int32_t)-43260,
    (int32_t)-1613174,
    (int32_t)495491);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)27U,
    (int32_t)819034,
    (int32_t)909542,
    (int32_t)1859098,
    (int32_t)900702);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)28U,
    (int32_t)-3193378,
    (int32_t)-1197226,
    (int32_t)-3759364,
    (int32_t)-3520352);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)29U,
    (int32_t)3513181,
    (int32_t)-1235728,
    (int32_t)2434439,
    (int32_t)266997);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)30U,
    (int32_t)-3562462,
    (int32_t)-2446433,
    (int32_t)2244091,
    (int32_t)-3342478);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (size_t)31U,
    (int32_t)3817976,
    (int32_t)2316500,
    (int32_t)3407706,
    (int32_t)2091667);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta0,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta0,
    (size_t)0U,
    (size_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta0,
    (size_t)1U,
    (size_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta1,
    (size_t)4U,
    (size_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta1,
    (size_t)5U,
    (size_t)2U);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(
  Eurydice_arr_a4 *re,
  size_t index,
  int32_t zeta_00,
  int32_t zeta_01
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(&re->data[index],
    zeta_00,
    zeta_01);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)0U,
    (int32_t)3839961,
    (int32_t)-3628969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)1U,
    (int32_t)-3881060,
    (int32_t)-3019102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)2U,
    (int32_t)-1439742,
    (int32_t)-812732);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)3U,
    (int32_t)-1584928,
    (int32_t)1285669);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)4U,
    (int32_t)1341330,
    (int32_t)1315589);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)5U,
    (int32_t)-177440,
    (int32_t)-2409325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)6U,
    (int32_t)-1851402,
    (int32_t)3159746);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)7U,
    (int32_t)-3553272,
    (int32_t)189548);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)8U,
    (int32_t)-1316856,
    (int32_t)759969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)9U,
    (int32_t)-210977,
    (int32_t)2389356);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)10U,
    (int32_t)-3249728,
    (int32_t)1653064);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)11U,
    (int32_t)-8578,
    (int32_t)-3724342);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)12U,
    (int32_t)3958618,
    (int32_t)904516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)13U,
    (int32_t)-1100098,
    (int32_t)44288);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)14U,
    (int32_t)3097992,
    (int32_t)508951);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)15U,
    (int32_t)264944,
    (int32_t)-3343383);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)16U,
    (int32_t)-1430430,
    (int32_t)1852771);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)17U,
    (int32_t)1349076,
    (int32_t)-381987);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)18U,
    (int32_t)-1308169,
    (int32_t)-22981);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)19U,
    (int32_t)-1228525,
    (int32_t)-671102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)20U,
    (int32_t)-2477047,
    (int32_t)-411027);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)21U,
    (int32_t)-3693493,
    (int32_t)-2967645);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)22U,
    (int32_t)2715295,
    (int32_t)2147896);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)23U,
    (int32_t)-983419,
    (int32_t)3412210);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)24U,
    (int32_t)126922,
    (int32_t)-3632928);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)25U,
    (int32_t)-3157330,
    (int32_t)-3190144);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)26U,
    (int32_t)-1000202,
    (int32_t)-4083598);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)27U,
    (int32_t)1939314,
    (int32_t)-1257611);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)28U,
    (int32_t)-1585221,
    (int32_t)2176455);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)29U,
    (int32_t)3475950,
    (int32_t)-1452451);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)30U,
    (int32_t)-3041255,
    (int32_t)-3677745);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (size_t)31U,
    (int32_t)-1528703,
    (int32_t)-3930395);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(
  Eurydice_arr_d4 *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (size_t)0U,
    (size_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (size_t)1U,
    (size_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (size_t)2U,
    (size_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (size_t)3U,
    (size_t)4U);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(
  Eurydice_arr_a4 *re,
  size_t index,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(&re->data[index], zeta1);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)0U,
    (int32_t)-2797779);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)1U,
    (int32_t)2071892);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)2U,
    (int32_t)-2556880);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)3U,
    (int32_t)3900724);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)4U,
    (int32_t)3881043);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)5U,
    (int32_t)954230);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)6U,
    (int32_t)531354);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)7U,
    (int32_t)811944);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)8U,
    (int32_t)3699596);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)9U,
    (int32_t)-1600420);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)10U,
    (int32_t)-2140649);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)11U,
    (int32_t)3507263);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)12U,
    (int32_t)-3821735);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)13U,
    (int32_t)3505694);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)14U,
    (int32_t)-1643818);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)15U,
    (int32_t)-1699267);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)16U,
    (int32_t)-539299);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)17U,
    (int32_t)2348700);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)18U,
    (int32_t)-300467);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)19U,
    (int32_t)3539968);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)20U,
    (int32_t)-2867647);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)21U,
    (int32_t)3574422);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)22U,
    (int32_t)-3043716);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)23U,
    (int32_t)-3861115);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)24U,
    (int32_t)3915439);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)25U,
    (int32_t)-2537516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)26U,
    (int32_t)-3592148);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)27U,
    (int32_t)-1661693);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)28U,
    (int32_t)3530437);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)29U,
    (int32_t)3077325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)30U,
    (int32_t)95776);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re,
    (size_t)31U,
    (int32_t)2706023);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 280005
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_99(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)280005);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 4010497
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1c(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)2U; i < (size_t)2U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -19422
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_6b(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)4U; i < (size_t)4U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 1757237
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_44(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)6U; i < (size_t)6U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -3277672
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a8(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)8U; i < (size_t)8U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1399561
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1f(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)10U; i < (size_t)10U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= -3859737
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_95(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)12U; i < (size_t)12U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2118186
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3b(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)14U; i < (size_t)14U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2108549
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= 2619752
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_e4(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)18U; i < (size_t)18U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1119584
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_de(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)20U; i < (size_t)20U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -549488
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_05(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)22U; i < (size_t)22U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 3585928
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d9(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)24U; i < (size_t)24U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -1079900
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3a(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)26U; i < (size_t)26U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)-1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 1024112
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3b0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)28U; i < (size_t)28U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 2725464
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)30U; i < (size_t)30U + (size_t)1U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)1U],
      (int32_t)2725464);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_3(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_99(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1c(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_6b(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_44(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a8(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1f(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_95(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3b(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_e4(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_de(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_05(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d9(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3a(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3b0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a0(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 2
- ZETA= 2680103
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_990(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)2680103);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 3111497
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_6b0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)4U; i < (size_t)4U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -2884855
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a80(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)8U; i < (size_t)8U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)-2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= 3119733
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_950(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)12U; i < (size_t)12U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= -2091905
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)-2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -359251
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_de0(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)20U; i < (size_t)20U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)-359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 2353451
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d90(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)24U; i < (size_t)24U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 1826347
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3b1(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)28U; i < (size_t)28U + (size_t)2U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)2U],
      (int32_t)1826347);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_4(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_990(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_6b0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a80(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_950(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_de0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d90(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_3b1(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 4
- ZETA= 466468
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_991(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)4U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)4U],
      (int32_t)466468);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -876248
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a81(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)8U; i < (size_t)8U + (size_t)4U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)4U],
      (int32_t)-876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -777960
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a1(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)4U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)4U],
      (int32_t)-777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 237124
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d91(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)24U; i < (size_t)24U + (size_t)4U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)4U],
      (int32_t)237124);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_5(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_991(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_a81(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a1(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d91(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 8
- ZETA= -518909
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_992(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)8U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)8U],
      (int32_t)-518909);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -2608894
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a2(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)16U; i < (size_t)16U + (size_t)8U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)8U],
      (int32_t)-2608894);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_6(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_992(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_7a2(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_993(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)0U + (size_t)16U; i++)
  {
    size_t j = i;
    Eurydice_arr_d4 rej = re->data[j];
    Eurydice_arr_d4 rejs = re->data[j + (size_t)16U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->data[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->data[j + (size_t)16U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[j +
        (size_t)16U],
      (int32_t)25847);
  }
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_993(re);
}

static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_3(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_4(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_5(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_6(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(re);
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->data[i0],
      (int32_t)41978);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void
libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(Eurydice_arr_a4 *simd_units)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(simd_units);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.arithmetic.shift_left_then_reduce
with const generics
- SHIFT_BY= 0
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_shift_left_then_reduce_c3(Eurydice_arr_d4 *simd_unit)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    simd_unit->data[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_reduce_element(simd_unit->data[i0] <<
          (uint32_t)(int32_t)0);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline void libcrux_ml_dsa_simd_portable_reduce_65(Eurydice_arr_a4 *simd_units)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_arithmetic_shift_left_then_reduce_c3(&simd_units->data[i0]);
  }
}

typedef struct Eurydice_borrow_slice_u8_x2_s
{
  Eurydice_borrow_slice_u8 fst;
  Eurydice_borrow_slice_u8 snd;
}
Eurydice_borrow_slice_u8_x2;

/**
A monomorphic instance of libcrux_ml_dsa.polynomial.PolynomialRingElement
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients

*/
typedef Eurydice_arr_a4 libcrux_ml_dsa_polynomial_PolynomialRingElement_e8;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $11size_t
*/
typedef struct Eurydice_arr_58_s { Eurydice_arr_a4 data[11U]; } Eurydice_arr_58;

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.zero_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static inline Eurydice_arr_a4 libcrux_ml_dsa_polynomial_zero_ff_37(void)
{
  Eurydice_arr_a4 lit;
  Eurydice_arr_d4 repeat_expression[32U];
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    repeat_expression[i] = libcrux_ml_dsa_simd_portable_zero_65();
  }
  memcpy(lit.data, repeat_expression, (size_t)32U * sizeof (Eurydice_arr_d4));
  return lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
typedef struct Eurydice_dst_ref_mut_e7_s
{
  Eurydice_arr_a4 *ptr;
  size_t meta;
}
Eurydice_dst_ref_mut_e7;

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
typedef struct Eurydice_dst_ref_shared_e7_s
{
  const Eurydice_arr_a4 *ptr;
  size_t meta;
}
Eurydice_dst_ref_shared_e7;

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_4
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(
  Eurydice_borrow_slice_u8 randomness,
  size_t *sampled_coefficients,
  Eurydice_arr_13 *out
)
{
  bool done = false;
  for (size_t i = (size_t)0U; i < randomness.meta / (size_t)4U; i++)
  {
    size_t _cloop_i = i;
    Eurydice_borrow_slice_u8
    random_bytes =
      Eurydice_slice_subslice_shared_7e(randomness,
        ((core_ops_range_Range_08){ _cloop_i * (size_t)4U, _cloop_i * (size_t)4U + (size_t)4U }));
    if (!done)
    {
      size_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(random_bytes,
          Eurydice_array_to_subslice_from_mut_96(out, sampled_coefficients[0U]));
      sampled_coefficients[0U] = sampled_coefficients[0U] + sampled;
      if (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        done = true;
      }
    }
  }
  return done;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(
  Eurydice_borrow_slice_u8 randomness,
  size_t *sampled_coefficients,
  Eurydice_arr_13 *out
)
{
  bool done = false;
  for (size_t i = (size_t)0U; i < randomness.meta / (size_t)4U; i++)
  {
    size_t _cloop_i = i;
    Eurydice_borrow_slice_u8
    random_bytes =
      Eurydice_slice_subslice_shared_7e(randomness,
        ((core_ops_range_Range_08){ _cloop_i * (size_t)4U, _cloop_i * (size_t)4U + (size_t)4U }));
    if (!done)
    {
      size_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(random_bytes,
          Eurydice_array_to_subslice_from_mut_96(out, sampled_coefficients[0U]));
      sampled_coefficients[0U] = sampled_coefficients[0U] + sampled;
      if (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        done = true;
      }
    }
  }
  return done;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 randomness,
  size_t *sampled,
  Eurydice_arr_13 *out
)
{
  switch (eta)
  {
    case libcrux_ml_dsa_constants_Eta_Two:
      {
        break;
      }
    case libcrux_ml_dsa_constants_Eta_Four:
      {
        return
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(randomness,
            sampled,
            out);
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  return
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(randomness,
      sampled,
      out);
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.from_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static inline void
libcrux_ml_dsa_polynomial_from_i32_array_ff_37(
  Eurydice_dst_ref_shared_fc array,
  Eurydice_arr_a4 *result
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_from_coefficient_array_65(Eurydice_slice_subslice_shared_46(array,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT
          }
        )),
      &result->data[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_four_error_ring_elements
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 seed,
  uint16_t start_index,
  Eurydice_dst_ref_mut_e7 re
)
{
  Eurydice_arr_a2 seed0 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, start_index);
  Eurydice_arr_a2
  seed1 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, (uint32_t)start_index + 1U);
  Eurydice_arr_a2
  seed2 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, (uint32_t)start_index + 2U);
  Eurydice_arr_a2
  seed3 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, (uint32_t)start_index + 3U);
  libcrux_ml_dsa_hash_functions_portable_Shake256X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(Eurydice_array_to_slice_shared_39(&seed0),
      Eurydice_array_to_slice_shared_39(&seed1),
      Eurydice_array_to_slice_shared_39(&seed2),
      Eurydice_array_to_slice_shared_39(&seed3));
  Eurydice_arr_3d_x4
  randomnesses0 = libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4_9b(&state);
  Eurydice_arr_380 out = { { { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } } } };
  size_t sampled0 = (size_t)0U;
  size_t sampled1 = (size_t)0U;
  size_t sampled2 = (size_t)0U;
  size_t sampled3 = (size_t)0U;
  libcrux_ml_dsa_constants_Eta uu____0 = eta;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____0,
      Eurydice_array_to_slice_shared_d4(&randomnesses0.fst),
      &sampled0,
      out.data);
  libcrux_ml_dsa_constants_Eta uu____1 = eta;
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____1,
      Eurydice_array_to_slice_shared_d4(&randomnesses0.snd),
      &sampled1,
      &out.data[1U]);
  libcrux_ml_dsa_constants_Eta uu____2 = eta;
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____2,
      Eurydice_array_to_slice_shared_d4(&randomnesses0.thd),
      &sampled2,
      &out.data[2U]);
  libcrux_ml_dsa_constants_Eta uu____3 = eta;
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____3,
      Eurydice_array_to_slice_shared_d4(&randomnesses0.f3),
      &sampled3,
      &out.data[3U]);
  while (true)
  {
    if (done0)
    {
      if (done1)
      {
        if (done2)
        {
          if (done3)
          {
            break;
          }
          else
          {
            Eurydice_arr_3d_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4_9b(&state);
            if (!done0)
            {
              libcrux_ml_dsa_constants_Eta uu____4 = eta;
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____4,
                  Eurydice_array_to_slice_shared_d4(&randomnesses.fst),
                  &sampled0,
                  out.data);
            }
            if (!done1)
            {
              libcrux_ml_dsa_constants_Eta uu____5 = eta;
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____5,
                  Eurydice_array_to_slice_shared_d4(&randomnesses.snd),
                  &sampled1,
                  &out.data[1U]);
            }
            if (!done2)
            {
              libcrux_ml_dsa_constants_Eta uu____6 = eta;
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____6,
                  Eurydice_array_to_slice_shared_d4(&randomnesses.thd),
                  &sampled2,
                  &out.data[2U]);
            }
            if (!done3)
            {
              libcrux_ml_dsa_constants_Eta uu____7 = eta;
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____7,
                  Eurydice_array_to_slice_shared_d4(&randomnesses.f3),
                  &sampled3,
                  &out.data[3U]);
            }
          }
        }
        else
        {
          Eurydice_arr_3d_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4_9b(&state);
          if (!done0)
          {
            libcrux_ml_dsa_constants_Eta uu____8 = eta;
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____8,
                Eurydice_array_to_slice_shared_d4(&randomnesses.fst),
                &sampled0,
                out.data);
          }
          if (!done1)
          {
            libcrux_ml_dsa_constants_Eta uu____9 = eta;
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____9,
                Eurydice_array_to_slice_shared_d4(&randomnesses.snd),
                &sampled1,
                &out.data[1U]);
          }
          if (!done2)
          {
            libcrux_ml_dsa_constants_Eta uu____10 = eta;
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____10,
                Eurydice_array_to_slice_shared_d4(&randomnesses.thd),
                &sampled2,
                &out.data[2U]);
          }
          if (!done3)
          {
            libcrux_ml_dsa_constants_Eta uu____11 = eta;
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____11,
                Eurydice_array_to_slice_shared_d4(&randomnesses.f3),
                &sampled3,
                &out.data[3U]);
          }
        }
      }
      else
      {
        Eurydice_arr_3d_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4_9b(&state);
        if (!done0)
        {
          libcrux_ml_dsa_constants_Eta uu____12 = eta;
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____12,
              Eurydice_array_to_slice_shared_d4(&randomnesses.fst),
              &sampled0,
              out.data);
        }
        if (!done1)
        {
          libcrux_ml_dsa_constants_Eta uu____13 = eta;
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____13,
              Eurydice_array_to_slice_shared_d4(&randomnesses.snd),
              &sampled1,
              &out.data[1U]);
        }
        if (!done2)
        {
          libcrux_ml_dsa_constants_Eta uu____14 = eta;
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____14,
              Eurydice_array_to_slice_shared_d4(&randomnesses.thd),
              &sampled2,
              &out.data[2U]);
        }
        if (!done3)
        {
          libcrux_ml_dsa_constants_Eta uu____15 = eta;
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____15,
              Eurydice_array_to_slice_shared_d4(&randomnesses.f3),
              &sampled3,
              &out.data[3U]);
        }
      }
    }
    else
    {
      Eurydice_arr_3d_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_x4_9b(&state);
      if (!done0)
      {
        libcrux_ml_dsa_constants_Eta uu____16 = eta;
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____16,
            Eurydice_array_to_slice_shared_d4(&randomnesses.fst),
            &sampled0,
            out.data);
      }
      if (!done1)
      {
        libcrux_ml_dsa_constants_Eta uu____17 = eta;
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____17,
            Eurydice_array_to_slice_shared_d4(&randomnesses.snd),
            &sampled1,
            &out.data[1U]);
      }
      if (!done2)
      {
        libcrux_ml_dsa_constants_Eta uu____18 = eta;
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____18,
            Eurydice_array_to_slice_shared_d4(&randomnesses.thd),
            &sampled2,
            &out.data[2U]);
      }
      if (!done3)
      {
        libcrux_ml_dsa_constants_Eta uu____19 = eta;
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____19,
            Eurydice_array_to_slice_shared_d4(&randomnesses.f3),
            &sampled3,
            &out.data[3U]);
      }
    }
  }
  size_t max0 = (size_t)start_index + (size_t)4U;
  size_t max;
  if (re.meta < max0)
  {
    max = re.meta;
  }
  else
  {
    max = max0;
  }
  for (size_t i = (size_t)start_index; i < max; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_20(&out.data[i0 %
          (size_t)4U]),
      &re.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.sample_s1_and_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_e7 s1_s2
)
{
  size_t len = s1_s2.meta;
  for (size_t i = (size_t)0U; i < len / (size_t)4U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      seed,
      4U * (uint32_t)(uint16_t)i0,
      s1_s2);
  }
  size_t remainder = len % (size_t)4U;
  if (remainder != (size_t)0U)
  {
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      seed,
      (uint16_t)(len - remainder),
      s1_s2);
  }
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
static inline Eurydice_dst_ref_mut_e7 Eurydice_array_to_slice_mut_71(Eurydice_arr_58 *a)
{
  Eurydice_dst_ref_mut_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)11U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $6size_t
*/
typedef struct Eurydice_arr_a3_s { Eurydice_arr_a4 data[6U]; } Eurydice_arr_a3;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $30size_t
*/
typedef struct Eurydice_arr_a1_s { Eurydice_arr_a4 data[30U]; } Eurydice_arr_a1;

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_field_modulus
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(
  Eurydice_borrow_slice_u8 randomness,
  size_t *sampled_coefficients,
  Eurydice_arr_13 *out
)
{
  bool done = false;
  for (size_t i = (size_t)0U; i < randomness.meta / (size_t)24U; i++)
  {
    size_t _cloop_i = i;
    Eurydice_borrow_slice_u8
    random_bytes =
      Eurydice_slice_subslice_shared_7e(randomness,
        ((core_ops_range_Range_08){ _cloop_i * (size_t)24U, _cloop_i * (size_t)24U + (size_t)24U }));
    if (!done)
    {
      size_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_field_modulus_65(random_bytes,
          Eurydice_array_to_subslice_from_mut_96(out, sampled_coefficients[0U]));
      sampled_coefficients[0U] = sampled_coefficients[0U] + sampled;
      if (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        done = true;
      }
    }
  }
  return done;
}

/**
 Sample and write out up to four ring elements.

 If i <= `elements_requested`, a field element with domain separated
 seed according to the provided index is generated in
 `tmp_stack[i]`. After successful rejection sampling in
 `tmp_stack[i]`, the ring element is written to `matrix` at the
 provided index in `indices[i]`.
 `rand_stack` is a working buffer that holds initial Shake output.
*/
/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_up_to_four_ring_elements_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_63(
  size_t columns,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_e7 matrix,
  Eurydice_arr_12 *rand_stack0,
  Eurydice_arr_12 *rand_stack1,
  Eurydice_arr_12 *rand_stack2,
  Eurydice_arr_12 *rand_stack3,
  Eurydice_dst_ref_mut_4c tmp_stack,
  size_t start_index,
  size_t elements_requested
)
{
  Eurydice_arr_48
  seed0 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_index, columns));
  Eurydice_arr_48
  seed1 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_index + (size_t)1U,
        columns));
  Eurydice_arr_48
  seed2 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_index + (size_t)2U,
        columns));
  Eurydice_arr_48
  seed3 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_index + (size_t)3U,
        columns));
  libcrux_ml_dsa_hash_functions_portable_Shake128X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_11(Eurydice_array_to_slice_shared_8d(&seed0),
      Eurydice_array_to_slice_shared_8d(&seed1),
      Eurydice_array_to_slice_shared_8d(&seed2),
      Eurydice_array_to_slice_shared_8d(&seed3));
  libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks_11(&state,
    rand_stack0,
    rand_stack1,
    rand_stack2,
    rand_stack3);
  size_t sampled0 = (size_t)0U;
  size_t sampled1 = (size_t)0U;
  size_t sampled2 = (size_t)0U;
  size_t sampled3 = (size_t)0U;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_a8(rand_stack0),
      &sampled0,
      tmp_stack.ptr);
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_a8(rand_stack1),
      &sampled1,
      &tmp_stack.ptr[1U]);
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_a8(rand_stack2),
      &sampled2,
      &tmp_stack.ptr[2U]);
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_a8(rand_stack3),
      &sampled3,
      &tmp_stack.ptr[3U]);
  while (true)
  {
    if (done0)
    {
      if (done1)
      {
        if (done2)
        {
          if (done3)
          {
            break;
          }
          else
          {
            Eurydice_arr_27_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_11(&state);
            if (!done0)
            {
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.fst),
                  &sampled0,
                  tmp_stack.ptr);
            }
            if (!done1)
            {
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.snd),
                  &sampled1,
                  &tmp_stack.ptr[1U]);
            }
            if (!done2)
            {
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.thd),
                  &sampled2,
                  &tmp_stack.ptr[2U]);
            }
            if (!done3)
            {
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.f3),
                  &sampled3,
                  &tmp_stack.ptr[3U]);
            }
          }
        }
        else
        {
          Eurydice_arr_27_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_11(&state);
          if (!done0)
          {
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.fst),
                &sampled0,
                tmp_stack.ptr);
          }
          if (!done1)
          {
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.snd),
                &sampled1,
                &tmp_stack.ptr[1U]);
          }
          if (!done2)
          {
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.thd),
                &sampled2,
                &tmp_stack.ptr[2U]);
          }
          if (!done3)
          {
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.f3),
                &sampled3,
                &tmp_stack.ptr[3U]);
          }
        }
      }
      else
      {
        Eurydice_arr_27_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_11(&state);
        if (!done0)
        {
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.fst),
              &sampled0,
              tmp_stack.ptr);
        }
        if (!done1)
        {
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.snd),
              &sampled1,
              &tmp_stack.ptr[1U]);
        }
        if (!done2)
        {
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.thd),
              &sampled2,
              &tmp_stack.ptr[2U]);
        }
        if (!done3)
        {
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.f3),
              &sampled3,
              &tmp_stack.ptr[3U]);
        }
      }
    }
    else
    {
      Eurydice_arr_27_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_11(&state);
      if (!done0)
      {
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.fst),
            &sampled0,
            tmp_stack.ptr);
      }
      if (!done1)
      {
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.snd),
            &sampled1,
            &tmp_stack.ptr[1U]);
      }
      if (!done2)
      {
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.thd),
            &sampled2,
            &tmp_stack.ptr[2U]);
      }
      if (!done3)
      {
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_7b(&randomnesses.f3),
            &sampled3,
            &tmp_stack.ptr[3U]);
      }
    }
  }
  for (size_t i = (size_t)0U; i < elements_requested; i++)
  {
    size_t k = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_20(&tmp_stack.ptr[k]),
      &matrix.ptr[start_index + k]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.matrix_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_samplex4_matrix_flat_63(
  size_t columns,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_e7 matrix
)
{
  Eurydice_arr_12 rand_stack0 = { { 0U } };
  Eurydice_arr_12 rand_stack1 = { { 0U } };
  Eurydice_arr_12 rand_stack2 = { { 0U } };
  Eurydice_arr_12 rand_stack3 = { { 0U } };
  Eurydice_arr_380 tmp_stack = { { { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } } } };
  for (size_t i = (size_t)0U; i < matrix.meta / (size_t)4U + (size_t)1U; i++)
  {
    size_t start_index = i;
    size_t start_index0 = start_index * (size_t)4U;
    if (!(start_index0 >= matrix.meta))
    {
      size_t elements_requested;
      if (start_index0 + (size_t)4U <= matrix.meta)
      {
        elements_requested = (size_t)4U;
      }
      else
      {
        elements_requested = matrix.meta - start_index0;
      }
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_63(columns,
        seed,
        matrix,
        &rand_stack0,
        &rand_stack1,
        &rand_stack2,
        &rand_stack3,
        Eurydice_array_to_slice_mut_f6(&tmp_stack),
        start_index0,
        elements_requested);
      continue;
    }
    break;
  }
}

/**
This function found in impl {libcrux_ml_dsa::samplex4::X4Sampler for libcrux_ml_dsa::samplex4::portable::PortableSampler}
*/
/**
A monomorphic instance of libcrux_ml_dsa.samplex4.portable.matrix_flat_a8
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static inline void
libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(
  size_t columns,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_e7 matrix
)
{
  libcrux_ml_dsa_samplex4_matrix_flat_63(columns, seed, matrix);
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
static inline Eurydice_dst_ref_mut_e7 Eurydice_array_to_slice_mut_710(Eurydice_arr_a1 *a)
{
  Eurydice_dst_ref_mut_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)30U;
  return lit;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $5size_t
*/
typedef struct Eurydice_arr_b0_s { Eurydice_arr_a4 data[5U]; } Eurydice_arr_b0;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
static inline Eurydice_dst_ref_mut_e7 Eurydice_array_to_slice_mut_711(Eurydice_arr_b0 *a)
{
  Eurydice_dst_ref_mut_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)5U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
static inline Eurydice_dst_ref_shared_e7
Eurydice_array_to_subslice_shared_c3(const Eurydice_arr_58 *a, core_ops_range_Range_08 r)
{
  return ((Eurydice_dst_ref_shared_e7){ a->data + r.start, r.end - r.start });
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void libcrux_ml_dsa_ntt_ntt_37(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_65(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt_multiply_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(Eurydice_arr_a4 *lhs, const Eurydice_arr_a4 *rhs)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_montgomery_multiply_65(&lhs->data[i0], &rhs->data[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.add_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_polynomial_add_ff_37(Eurydice_arr_a4 *self, const Eurydice_arr_a4 *rhs)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_add_65(&self->data[i0], &rhs->data[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.reduce
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void libcrux_ml_dsa_ntt_reduce_37(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_reduce_65(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.invert_ntt_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(Eurydice_arr_a4 *re)
{
  libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(re);
}

/**
 Compute InvertNTT(Â ◦ ŝ₁) + s₂
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_as1_plus_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_matrix_compute_as1_plus_s2_37(
  size_t rows_in_a,
  size_t columns_in_a,
  Eurydice_dst_ref_mut_e7 a_as_ntt,
  Eurydice_dst_ref_shared_e7 s1_ntt,
  Eurydice_dst_ref_shared_e7 s1_s2,
  Eurydice_dst_ref_mut_e7 result
)
{
  for (size_t i0 = (size_t)0U; i0 < rows_in_a; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < columns_in_a; i++)
    {
      size_t j = i;
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&a_as_ntt.ptr[i1 * columns_in_a + j],
        &s1_ntt.ptr[j]);
      libcrux_ml_dsa_polynomial_add_ff_37(&result.ptr[i1], &a_as_ntt.ptr[i1 * columns_in_a + j]);
    }
  }
  for (size_t i = (size_t)0U; i < result.meta; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_ntt_reduce_37(&result.ptr[i0]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&result.ptr[i0]);
    libcrux_ml_dsa_polynomial_add_ff_37(&result.ptr[i0], &s1_s2.ptr[columns_in_a + i0]);
  }
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
static inline Eurydice_dst_ref_shared_e7
Eurydice_array_to_slice_shared_71(const Eurydice_arr_b0 *a)
{
  Eurydice_dst_ref_shared_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)5U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
static inline Eurydice_dst_ref_shared_e7
Eurydice_array_to_slice_shared_710(const Eurydice_arr_58 *a)
{
  Eurydice_dst_ref_shared_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)11U;
  return lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
static inline Eurydice_dst_ref_mut_e7 Eurydice_array_to_slice_mut_712(Eurydice_arr_a3 *a)
{
  Eurydice_dst_ref_mut_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)6U;
  return lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.power2round_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_arithmetic_power2round_vector_37(
  Eurydice_dst_ref_mut_e7 t,
  Eurydice_dst_ref_mut_e7 t1
)
{
  for (size_t i0 = (size_t)0U; i0 < t.meta; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)32U; i++)
    {
      size_t j = i;
      libcrux_ml_dsa_simd_portable_power2round_65(&t.ptr[i1].data[j], &t1.ptr[i1].data[j]);
    }
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_t1_serialize_37(
  const Eurydice_arr_a4 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_d4 *simd_unit = &re->data[i0];
    libcrux_ml_dsa_simd_portable_t1_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_BYTES_PER_SIMD_UNIT,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_BYTES_PER_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_verification_key_generate_serialized_37(
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_shared_e7 t1,
  Eurydice_mut_borrow_slice_u8 verification_key_serialized
)
{
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(verification_key_serialized,
      ((core_ops_range_Range_08){ (size_t)0U, LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE })),
    seed,
    uint8_t);
  for (size_t i = (size_t)0U; i < t1.meta; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_a4 *ring_element = &t1.ptr[i0];
    size_t
    offset =
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE +
        i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1S_SIZE;
    libcrux_ml_dsa_encoding_t1_serialize_37(ring_element,
      Eurydice_slice_subslice_mut_7e(verification_key_serialized,
        (
          (core_ops_range_Range_08){
            offset,
            offset + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1S_SIZE
          }
        )));
  }
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
static inline Eurydice_dst_ref_shared_e7
Eurydice_array_to_slice_shared_711(const Eurydice_arr_a3 *a)
{
  Eurydice_dst_ref_shared_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)6U;
  return lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 64
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_24(
  Eurydice_borrow_slice_u8 input,
  Eurydice_arr_060 *out
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_d8(out), input);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 64
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_61_24(
  Eurydice_borrow_slice_u8 input,
  Eurydice_arr_060 *out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_24(input, out);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_error_serialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  const Eurydice_arr_a4 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  size_t output_bytes_per_simd_unit = libcrux_ml_dsa_encoding_error_chunk_size(eta);
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_d4 *simd_unit = &re->data[i0];
    libcrux_ml_dsa_simd_portable_error_serialize_65(eta,
      simd_unit,
      Eurydice_slice_subslice_mut_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * output_bytes_per_simd_unit,
            (i0 + (size_t)1U) * output_bytes_per_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_t0_serialize_37(
  const Eurydice_arr_a4 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_d4 *simd_unit = &re->data[i0];
    libcrux_ml_dsa_simd_portable_t0_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signing_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_signing_key_generate_serialized_2e(
  libcrux_ml_dsa_constants_Eta eta,
  size_t error_ring_element_size,
  Eurydice_borrow_slice_u8 seed_matrix,
  Eurydice_borrow_slice_u8 seed_signing,
  Eurydice_borrow_slice_u8 verification_key,
  Eurydice_dst_ref_shared_e7 s1_2,
  Eurydice_dst_ref_shared_e7 t0,
  Eurydice_mut_borrow_slice_u8 signing_key_serialized
)
{
  size_t offset = (size_t)0U;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(signing_key_serialized,
      ((core_ops_range_Range_08){ offset, offset + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE })),
    seed_matrix,
    uint8_t);
  offset = offset + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(signing_key_serialized,
      ((core_ops_range_Range_08){ offset, offset + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_SIZE })),
    seed_signing,
    uint8_t);
  offset = offset + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_SIZE;
  Eurydice_arr_060 verification_key_hash = { { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_24(verification_key,
    &verification_key_hash);
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(signing_key_serialized,
      (
        (core_ops_range_Range_08){
          offset,
          offset + LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_KEY_HASH
        }
      )),
    Eurydice_array_to_slice_shared_d8(&verification_key_hash),
    uint8_t);
  offset = offset + LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_KEY_HASH;
  for (size_t i = (size_t)0U; i < s1_2.meta; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_encoding_error_serialize_37(eta,
      &s1_2.ptr[i0],
      Eurydice_slice_subslice_mut_7e(signing_key_serialized,
        ((core_ops_range_Range_08){ offset, offset + error_ring_element_size })));
    offset = offset + error_ring_element_size;
  }
  for (size_t i = (size_t)0U; i < t0.meta; i++)
  {
    size_t _cloop_j = i;
    const Eurydice_arr_a4 *ring_element = &t0.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_t0_serialize_37(ring_element,
      Eurydice_slice_subslice_mut_7e(signing_key_serialized,
        (
          (core_ops_range_Range_08){
            offset,
            offset + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE
          }
        )));
    offset = offset + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_key_pair_5a(
  Eurydice_arr_600 randomness,
  Eurydice_mut_borrow_slice_u8 signing_key,
  Eurydice_mut_borrow_slice_u8 verification_key
)
{
  Eurydice_arr_d1 seed_expanded0 = { { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_to_slice_shared_6e(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_to_slice_shared_26(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_to_slice_mut_18(&seed_expanded0));
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_18(&seed_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 seed_expanded = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(seed_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_ERROR_VECTORS_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_error_vectors = uu____1.fst;
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.snd;
  Eurydice_arr_58 s1_s2;
  Eurydice_arr_a4 repeat_expression0[11U];
  for (size_t i = (size_t)0U; i < (size_t)11U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(s1_s2.data, repeat_expression0, (size_t)11U * sizeof (Eurydice_arr_a4));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    seed_for_error_vectors,
    Eurydice_array_to_slice_mut_71(&s1_s2));
  Eurydice_arr_a3 t0;
  Eurydice_arr_a4 repeat_expression1[6U];
  for (size_t i = (size_t)0U; i < (size_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(t0.data, repeat_expression1, (size_t)6U * sizeof (Eurydice_arr_a4));
  Eurydice_arr_a1 a_as_ntt;
  Eurydice_arr_a4 repeat_expression2[30U];
  for (size_t i = (size_t)0U; i < (size_t)30U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(a_as_ntt.data, repeat_expression2, (size_t)30U * sizeof (Eurydice_arr_a4));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_710(&a_as_ntt));
  Eurydice_arr_b0 s1_ntt;
  Eurydice_arr_a4 repeat_expression3[5U];
  for (size_t i = (size_t)0U; i < (size_t)5U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(s1_ntt.data, repeat_expression3, (size_t)5U * sizeof (Eurydice_arr_a4));
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_711(&s1_ntt),
    Eurydice_array_to_subslice_shared_c3(&s1_s2,
      ((core_ops_range_Range_08){ (size_t)0U, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A })),
    Eurydice_arr_a4);
  for (size_t i = (size_t)0U; i < (size_t)5U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.data[i0]);
  }
  libcrux_ml_dsa_matrix_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
    Eurydice_array_to_slice_mut_710(&a_as_ntt),
    Eurydice_array_to_slice_shared_71(&s1_ntt),
    Eurydice_array_to_slice_shared_710(&s1_s2),
    Eurydice_array_to_slice_mut_712(&t0));
  Eurydice_arr_a3 t1;
  Eurydice_arr_a4 repeat_expression[6U];
  for (size_t i = (size_t)0U; i < (size_t)6U; i++)
  {
    repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(t1.data, repeat_expression, (size_t)6U * sizeof (Eurydice_arr_a4));
  libcrux_ml_dsa_arithmetic_power2round_vector_37(Eurydice_array_to_slice_mut_712(&t0),
    Eurydice_array_to_slice_mut_712(&t1));
  libcrux_ml_dsa_encoding_verification_key_generate_serialized_37(seed_for_a,
    Eurydice_array_to_slice_shared_711(&t1),
    verification_key);
  libcrux_ml_dsa_encoding_signing_key_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE,
    seed_for_a,
    seed_for_signing,
    ((Eurydice_borrow_slice_u8){ verification_key.ptr, verification_key.meta }),
    Eurydice_array_to_slice_shared_710(&s1_s2),
    Eurydice_array_to_slice_shared_711(&t0),
    signing_key);
}

/**
 Generate key pair.
*/
static inline void
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_key_pair(
  Eurydice_arr_600 randomness,
  Eurydice_arr_d10 *signing_key,
  Eurydice_arr_4a *verification_key
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_key_pair_5a(randomness,
    Eurydice_array_to_slice_mut_ef(signing_key),
    Eurydice_array_to_slice_mut_5b(verification_key));
}

/**
 Generate an ML-DSA-65 Key Pair
*/
static inline libcrux_ml_dsa_types_MLDSAKeyPair_06
libcrux_ml_dsa_ml_dsa_65_portable_generate_key_pair(Eurydice_arr_600 randomness)
{
  Eurydice_arr_d10 signing_key = { { 0U } };
  Eurydice_arr_4a verification_key = { { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_key_pair(randomness,
    &signing_key,
    &verification_key);
  return
    (
      (libcrux_ml_dsa_types_MLDSAKeyPair_06){
        libcrux_ml_dsa_types_new_9b_09(signing_key),
        libcrux_ml_dsa_types_new_7f_97(verification_key)
      }
    );
}

/**
 Generate an ML-DSA-65 Key Pair
*/
static inline void
libcrux_ml_dsa_ml_dsa_65_portable_generate_key_pair_mut(
  Eurydice_arr_600 randomness,
  Eurydice_arr_d10 *signing_key,
  Eurydice_arr_4a *verification_key
)
{
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_key_pair(randomness,
    signing_key,
    verification_key);
}

/**
A monomorphic instance of core.option.Option
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext

*/
typedef struct Option_84_s
{
  Option_cb_tags tag;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext f0;
}
Option_84;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_error_deserialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a4 *result
)
{
  size_t chunk_size = libcrux_ml_dsa_encoding_error_chunk_size(eta);
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_error_deserialize_65(eta,
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * chunk_size, (i0 + (size_t)1U) * chunk_size })),
      &result->data[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(
  libcrux_ml_dsa_constants_Eta eta,
  size_t ring_element_size,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_dst_ref_mut_e7 ring_elements
)
{
  for (size_t i = (size_t)0U; i < serialized.meta / ring_element_size; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * ring_element_size,
            i0 * ring_element_size + ring_element_size
          }
        ));
    libcrux_ml_dsa_encoding_error_deserialize_37(eta, bytes, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_t0_deserialize_37(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a4 *result
)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_t0_deserialize_65(Eurydice_slice_subslice_shared_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT
          }
        )),
      &result->data[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_t0_deserialize_to_vector_then_ntt_37(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_dst_ref_mut_e7 ring_elements
)
{
  for
  (size_t
    i = (size_t)0U;
    i < serialized.meta / LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE;
    i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE,
            i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE +
              LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0S_SIZE
          }
        ));
    libcrux_ml_dsa_encoding_t0_deserialize_37(bytes, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
 This corresponds to line 6 in algorithm 7 in FIPS 204 (line 7 in algorithm
 8, resp.).

 If `domain_separation_context` is supplied, applies domain
 separation and length encoding to the context string,
 before appending the message (in the regular variant) or the
 pre-hash OID as well as the pre-hashed message digest. Otherwise,
 it is assumed that `message` already contains domain separation
 information.

 In FIPS 204 M' is the concatenation of the domain separated context, any
 potential pre-hash OID and the message (or the message pre-hash). We do not
 explicitely construct the concatenation in memory since it is of statically unknown
 length, but feed its components directly into the incremental XOF.

 Refer to line 10 of Algorithm 2 (and line 5 of Algorithm 3, resp.) in [FIPS
 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#section.5)
 for details on the domain separation for regular ML-DSA. Line
 23 of Algorithm 4 (and line 18 of Algorithm 5,resp.) describe domain separation for the HashMl-DSA
 variant.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.derive_message_representative
with types libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(
  Eurydice_borrow_slice_u8 verification_key_hash,
  const Option_84 *domain_separation_context,
  Eurydice_borrow_slice_u8 message,
  Eurydice_arr_060 *message_representative
)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake, verification_key_hash);
  if (domain_separation_context->tag == Some)
  {
    const
    libcrux_ml_dsa_pre_hash_DomainSeparationContext
    *domain_separation_context0 = &domain_separation_context->f0;
    libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *uu____0 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_f10
    lvalue0 =
      {
        {
          (uint8_t)core_option__core__option__Option_T__TraitClause_0___is_some(libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0),
            Eurydice_arr_cb,
            bool)
        }
      };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____0,
      Eurydice_array_to_slice_shared_07(&lvalue0));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_e2 *uu____1 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_f10
    lvalue = { { (uint8_t)libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0).meta } };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____1,
      Eurydice_array_to_slice_shared_07(&lvalue));
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0));
    const Option_b5 *uu____2 = libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0);
    if (uu____2->tag == Some)
    {
      const Eurydice_arr_cb *pre_hash_oid = &uu____2->f0;
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_to_slice_shared_da(pre_hash_oid));
    }
  }
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake, message);
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_to_slice_mut_d8(message_representative));
}

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_b0

*/
typedef struct Option_c8_s
{
  Option_cb_tags tag;
  Eurydice_arr_b0 f0;
}
Option_c8;

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 576
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_1b(
  Eurydice_borrow_slice_u8 input,
  Eurydice_arr_5f0 *out
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_fa(out), input);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 576
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_1b(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3,
  Eurydice_arr_5f0 *out0,
  Eurydice_arr_5f0 *out1,
  Eurydice_arr_5f0 *out2,
  Eurydice_arr_5f0 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_1b(input0, out0);
  libcrux_ml_dsa_hash_functions_portable_shake256_1b(input1, out1);
  libcrux_ml_dsa_hash_functions_portable_shake256_1b(input2, out2);
  libcrux_ml_dsa_hash_functions_portable_shake256_1b(input3, out3);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_gamma1_deserialize_37(
  size_t gamma1_exponent,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a4 *result
)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(Eurydice_slice_subslice_shared_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * (gamma1_exponent + (size_t)1U),
            (i0 + (size_t)1U) * (gamma1_exponent + (size_t)1U)
          }
        )),
      &result->data[i0],
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 640
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_c8(
  Eurydice_borrow_slice_u8 input,
  Eurydice_arr_c30 *out
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_7d(out), input);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 640
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_c8(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3,
  Eurydice_arr_c30 *out0,
  Eurydice_arr_c30 *out1,
  Eurydice_arr_c30 *out2,
  Eurydice_arr_c30 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_c8(input0, out0);
  libcrux_ml_dsa_hash_functions_portable_shake256_c8(input1, out1);
  libcrux_ml_dsa_hash_functions_portable_shake256_c8(input2, out2);
  libcrux_ml_dsa_hash_functions_portable_shake256_c8(input3, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 640
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_61_c8(
  Eurydice_borrow_slice_u8 input,
  Eurydice_arr_c30 *out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_c8(input, out);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 576
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_hash_functions_portable_shake256_61_1b(
  Eurydice_borrow_slice_u8 input,
  Eurydice_arr_5f0 *out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_1b(input, out);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_sample_sample_mask_ring_element_2e(
  const Eurydice_arr_a2 *seed,
  Eurydice_arr_a4 *result,
  size_t gamma1_exponent
)
{
  switch (gamma1_exponent)
  {
    case 17U:
      {
        break;
      }
    case 19U:
      {
        Eurydice_arr_c30 out = { { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_61_c8(Eurydice_array_to_slice_shared_39(seed),
          &out);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_7d0(&out),
          result);
        return;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  Eurydice_arr_5f0 out = { { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_1b(Eurydice_array_to_slice_shared_39(seed),
    &out);
  libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
    Eurydice_array_to_slice_shared_fa(&out),
    result);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_sample_sample_mask_vector_67(
  size_t dimension,
  size_t gamma1_exponent,
  const Eurydice_arr_060 *seed,
  uint16_t *domain_separator,
  Eurydice_dst_ref_mut_e7 mask
)
{
  Eurydice_arr_a2
  seed0 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_d8(seed),
      domain_separator[0U]);
  Eurydice_arr_a2
  seed1 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_d8(seed),
      (uint32_t)domain_separator[0U] + 1U);
  Eurydice_arr_a2
  seed2 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_d8(seed),
      (uint32_t)domain_separator[0U] + 2U);
  Eurydice_arr_a2
  seed3 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_d8(seed),
      (uint32_t)domain_separator[0U] + 3U);
  domain_separator[0U] = (uint32_t)domain_separator[0U] + 4U;
  switch (gamma1_exponent)
  {
    case 17U:
      {
        Eurydice_arr_5f0 out0 = { { 0U } };
        Eurydice_arr_5f0 out1 = { { 0U } };
        Eurydice_arr_5f0 out2 = { { 0U } };
        Eurydice_arr_5f0 out3 = { { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_1b(Eurydice_array_to_slice_shared_39(&seed0),
          Eurydice_array_to_slice_shared_39(&seed1),
          Eurydice_array_to_slice_shared_39(&seed2),
          Eurydice_array_to_slice_shared_39(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_fa(&out0),
          mask.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_fa(&out1),
          &mask.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_fa(&out2),
          &mask.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_fa(&out3),
          &mask.ptr[3U]);
        break;
      }
    case 19U:
      {
        Eurydice_arr_c30 out0 = { { 0U } };
        Eurydice_arr_c30 out1 = { { 0U } };
        Eurydice_arr_c30 out2 = { { 0U } };
        Eurydice_arr_c30 out3 = { { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_c8(Eurydice_array_to_slice_shared_39(&seed0),
          Eurydice_array_to_slice_shared_39(&seed1),
          Eurydice_array_to_slice_shared_39(&seed2),
          Eurydice_array_to_slice_shared_39(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_7d0(&out0),
          mask.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_7d0(&out1),
          &mask.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_7d0(&out2),
          &mask.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_7d0(&out3),
          &mask.ptr[3U]);
        break;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  for (size_t i = (size_t)4U; i < dimension; i++)
  {
    size_t i0 = i;
    Eurydice_arr_a2
    seed4 =
      libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_d8(seed),
        domain_separator[0U]);
    domain_separator[0U] = (uint32_t)domain_separator[0U] + 1U;
    libcrux_ml_dsa_sample_sample_mask_ring_element_2e(&seed4, &mask.ptr[i0], gamma1_exponent);
  }
}

/**
 Compute InvertNTT(Â ◦ ŷ)
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_matrix_x_mask
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_matrix_compute_matrix_x_mask_37(
  size_t rows_in_a,
  size_t columns_in_a,
  Eurydice_dst_ref_shared_e7 matrix,
  Eurydice_dst_ref_shared_e7 mask,
  Eurydice_dst_ref_mut_e7 result
)
{
  for (size_t i0 = (size_t)0U; i0 < rows_in_a; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < columns_in_a; i++)
    {
      size_t j = i;
      Eurydice_arr_a4 product = mask.ptr[j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&product, &matrix.ptr[i1 * columns_in_a + j]);
      libcrux_ml_dsa_polynomial_add_ff_37(&result.ptr[i1], &product);
    }
    libcrux_ml_dsa_ntt_reduce_37(&result.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&result.ptr[i1]);
  }
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
static inline Eurydice_dst_ref_shared_e7
Eurydice_array_to_slice_shared_712(const Eurydice_arr_a1 *a)
{
  Eurydice_dst_ref_shared_e7 lit;
  lit.ptr = a->data;
  lit.meta = (size_t)30U;
  return lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.decompose_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_arithmetic_decompose_vector_37(
  size_t dimension,
  int32_t gamma2,
  Eurydice_dst_ref_shared_e7 t,
  Eurydice_dst_ref_mut_e7 low,
  Eurydice_dst_ref_mut_e7 high
)
{
  for (size_t i0 = (size_t)0U; i0 < dimension; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)32U; i++)
    {
      size_t j = i;
      libcrux_ml_dsa_simd_portable_decompose_65(gamma2,
        &t.ptr[i1].data[j],
        &low.ptr[i1].data[j],
        &high.ptr[i1].data[j]);
    }
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_commitment_serialize_37(
  const Eurydice_arr_a4 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  size_t output_bytes_per_simd_unit = serialized.meta / ((size_t)8U * (size_t)4U);
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_d4 *simd_unit = &re->data[i0];
    libcrux_ml_dsa_simd_portable_commitment_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * output_bytes_per_simd_unit,
            (i0 + (size_t)1U) * output_bytes_per_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_commitment_serialize_vector_37(
  size_t ring_element_size,
  Eurydice_dst_ref_shared_e7 vector,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  size_t offset = (size_t)0U;
  for (size_t i = (size_t)0U; i < vector.meta; i++)
  {
    size_t _cloop_j = i;
    const Eurydice_arr_a4 *ring_element = &vector.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_commitment_serialize_37(ring_element,
      Eurydice_slice_subslice_mut_7e(serialized,
        ((core_ops_range_Range_08){ offset, offset + ring_element_size })));
    offset = offset + ring_element_size;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_challenge_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(
  Eurydice_borrow_slice_u8 seed,
  size_t number_of_ones,
  Eurydice_arr_a4 *re
)
{
  Eurydice_arr_26 state = libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(seed);
  Eurydice_arr_3d
  randomness0 = libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_61(&state);
  Eurydice_array_u8x8 arr;
  memcpy(arr.data,
    Eurydice_array_to_subslice_shared_360(&randomness0,
      ((core_ops_range_Range_08){ (size_t)0U, (size_t)8U })).ptr,
    (size_t)8U * sizeof (uint8_t));
  uint64_t
  signs =
    core_num__u64__from_le_bytes(unwrap_26_ab((Result_8e){ .tag = Ok, .val = { .case_Ok = arr } }));
  Eurydice_arr_c3 result = { { 0U } };
  size_t out_index = (size_t)256U - number_of_ones;
  bool
  done =
    libcrux_ml_dsa_sample_inside_out_shuffle(Eurydice_array_to_subslice_from_shared_8c(&randomness0,
        (size_t)8U),
      &out_index,
      &signs,
      &result);
  while (true)
  {
    if (done)
    {
      break;
    }
    else
    {
      Eurydice_arr_3d
      randomness = libcrux_ml_dsa_hash_functions_portable_squeeze_next_block_61(&state);
      done =
        libcrux_ml_dsa_sample_inside_out_shuffle(Eurydice_array_to_slice_shared_d4(&randomness),
          &out_index,
          &signs,
          &result);
    }
  }
  libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_200(&result),
    re);
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.vector_times_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_matrix_vector_times_ring_element_37(
  Eurydice_dst_ref_mut_e7 vector,
  const Eurydice_arr_a4 *ring_element
)
{
  for (size_t i = (size_t)0U; i < vector.meta; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&vector.ptr[i0], ring_element);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&vector.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.add_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_matrix_add_vectors_37(
  size_t dimension,
  Eurydice_dst_ref_mut_e7 lhs,
  Eurydice_dst_ref_shared_e7 rhs
)
{
  for (size_t i = (size_t)0U; i < dimension; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_polynomial_add_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.subtract_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_polynomial_subtract_ff_37(Eurydice_arr_a4 *self, const Eurydice_arr_a4 *rhs)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_subtract_65(&self->data[i0], &rhs->data[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.subtract_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_matrix_subtract_vectors_37(
  size_t dimension,
  Eurydice_dst_ref_mut_e7 lhs,
  Eurydice_dst_ref_shared_e7 rhs
)
{
  for (size_t i = (size_t)0U; i < dimension; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_polynomial_subtract_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.infinity_norm_exceeds_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE bool
libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(
  const Eurydice_arr_a4 *self,
  int32_t bound
)
{
  bool result = false;
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    bool uu____0;
    if (result)
    {
      uu____0 = true;
    }
    else
    {
      uu____0 = libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(&self->data[i0], bound);
    }
    result = uu____0;
  }
  return result;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.vector_infinity_norm_exceeds
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE bool
libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(
  Eurydice_dst_ref_shared_e7 vector,
  int32_t bound
)
{
  bool result = false;
  for (size_t i = (size_t)0U; i < vector.meta; i++)
  {
    size_t i0 = i;
    bool uu____0;
    if (result)
    {
      uu____0 = true;
    }
    else
    {
      uu____0 = libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(&vector.ptr[i0], bound);
    }
    result = uu____0;
  }
  return result;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.to_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static inline Eurydice_arr_c3
libcrux_ml_dsa_polynomial_to_i32_array_ff_37(const Eurydice_arr_a4 *self)
{
  Eurydice_arr_c3 result = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_to_coefficient_array_65(&self->data[i0],
      Eurydice_array_to_subslice_mut_7f(&result,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT
          }
        )));
  }
  return result;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.make_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE size_t
libcrux_ml_dsa_arithmetic_make_hint_37(
  Eurydice_dst_ref_shared_e7 low,
  Eurydice_dst_ref_shared_e7 high,
  int32_t gamma2,
  Eurydice_dst_ref_mut_22 hint
)
{
  size_t true_hints = (size_t)0U;
  Eurydice_arr_a4 hint_simd = libcrux_ml_dsa_polynomial_zero_ff_37();
  for (size_t i0 = (size_t)0U; i0 < low.meta; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)32U; i++)
    {
      size_t j = i;
      size_t
      one_hints_count =
        libcrux_ml_dsa_simd_portable_compute_hint_65(&low.ptr[i1].data[j],
          &high.ptr[i1].data[j],
          gamma2,
          &hint_simd.data[j]);
      true_hints = true_hints + one_hints_count;
    }
    Eurydice_arr_c3 uu____0 = libcrux_ml_dsa_polynomial_to_i32_array_ff_37(&hint_simd);
    hint.ptr[i1] = uu____0;
  }
  return true_hints;
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_gamma1_serialize_37(
  const Eurydice_arr_a4 *re,
  Eurydice_mut_borrow_slice_u8 serialized,
  size_t gamma1_exponent
)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_d4 *simd_unit = &re->data[i0];
    libcrux_ml_dsa_simd_portable_gamma1_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * (gamma1_exponent + (size_t)1U),
            (i0 + (size_t)1U) * (gamma1_exponent + (size_t)1U)
          }
        )),
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_signature_serialize_37(
  Eurydice_borrow_slice_u8 commitment_hash,
  Eurydice_dst_ref_shared_e7 signer_response,
  Eurydice_dst_ref_shared_22 hint,
  size_t commitment_hash_size,
  size_t columns_in_a,
  size_t rows_in_a,
  size_t gamma1_exponent,
  size_t gamma1_ring_element_size,
  size_t max_ones_in_hint,
  Eurydice_mut_borrow_slice_u8 signature
)
{
  size_t offset = (size_t)0U;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(signature,
      ((core_ops_range_Range_08){ offset, offset + commitment_hash_size })),
    commitment_hash,
    uint8_t);
  offset = offset + commitment_hash_size;
  for (size_t i = (size_t)0U; i < columns_in_a; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_serialize_37(&signer_response.ptr[i0],
      Eurydice_slice_subslice_mut_7e(signature,
        ((core_ops_range_Range_08){ offset, offset + gamma1_ring_element_size })),
      gamma1_exponent);
    offset = offset + gamma1_ring_element_size;
  }
  size_t true_hints_seen = (size_t)0U;
  for (size_t i0 = (size_t)0U; i0 < rows_in_a; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)256U; i++)
    {
      size_t j = i;
      if (hint.ptr[i1].data[j] == (int32_t)1)
      {
        signature.ptr[offset + true_hints_seen] = (uint8_t)j;
        true_hints_seen++;
      }
    }
    signature.ptr[offset + max_ones_in_hint + i1] = (uint8_t)true_hints_seen;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE Result_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_internal_5a(
  Eurydice_borrow_slice_u8 signing_key,
  Eurydice_borrow_slice_u8 message,
  Option_84 domain_separation_context,
  Eurydice_arr_600 randomness,
  Eurydice_arr_96 *signature
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(signing_key,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 remaining_serialized0 = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(remaining_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.fst;
  Eurydice_borrow_slice_u8 remaining_serialized1 = uu____1.snd;
  Eurydice_borrow_slice_u8_x2
  uu____2 =
    Eurydice_slice_split_at(remaining_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_KEY_HASH,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 verification_key_hash = uu____2.fst;
  Eurydice_borrow_slice_u8 remaining_serialized2 = uu____2.snd;
  Eurydice_borrow_slice_u8_x2
  uu____3 =
    Eurydice_slice_split_at(remaining_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_slice_u8 remaining_serialized = uu____3.snd;
  Eurydice_borrow_slice_u8_x2
  uu____4 =
    Eurydice_slice_split_at(remaining_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_slice_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_b0 s1_as_ntt;
  Eurydice_arr_a4 repeat_expression0[5U];
  for (size_t i = (size_t)0U; i < (size_t)5U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(s1_as_ntt.data, repeat_expression0, (size_t)5U * sizeof (Eurydice_arr_a4));
  Eurydice_arr_a3 s2_as_ntt;
  Eurydice_arr_a4 repeat_expression1[6U];
  for (size_t i = (size_t)0U; i < (size_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(s2_as_ntt.data, repeat_expression1, (size_t)6U * sizeof (Eurydice_arr_a4));
  Eurydice_arr_a3 t0_as_ntt;
  Eurydice_arr_a4 repeat_expression2[6U];
  for (size_t i = (size_t)0U; i < (size_t)6U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(t0_as_ntt.data, repeat_expression2, (size_t)6U * sizeof (Eurydice_arr_a4));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE,
    s1_serialized,
    Eurydice_array_to_slice_mut_711(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE,
    s2_serialized,
    Eurydice_array_to_slice_mut_712(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_to_vector_then_ntt_37(t0_serialized,
    Eurydice_array_to_slice_mut_712(&t0_as_ntt));
  Eurydice_arr_a1 matrix;
  Eurydice_arr_a4 repeat_expression3[30U];
  for (size_t i = (size_t)0U; i < (size_t)30U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(matrix.data, repeat_expression3, (size_t)30U * sizeof (Eurydice_arr_a4));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_710(&matrix));
  Eurydice_arr_060 message_representative = { { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(verification_key_hash,
    &domain_separation_context,
    message,
    &message_representative);
  Eurydice_arr_060 mask_seed = { { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, seed_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_to_slice_shared_6e(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_to_slice_shared_d8(&message_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_to_slice_mut_d8(&mask_seed));
  uint16_t domain_separator_for_mask = 0U;
  size_t attempt = (size_t)0U;
  Option_a6 commitment_hash0 = { None };
  Option_c8 signer_response0 = { None };
  Option_cb hint0 = { None };
  while (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_b0 mask;
    Eurydice_arr_a4 repeat_expression4[5U];
    for (size_t i = (size_t)0U; i < (size_t)5U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    memcpy(mask.data, repeat_expression4, (size_t)5U * sizeof (Eurydice_arr_a4));
    Eurydice_arr_a3 w0;
    Eurydice_arr_a4 repeat_expression5[6U];
    for (size_t i = (size_t)0U; i < (size_t)6U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    memcpy(w0.data, repeat_expression5, (size_t)6U * sizeof (Eurydice_arr_a4));
    Eurydice_arr_a3 commitment;
    Eurydice_arr_a4 repeat_expression6[6U];
    for (size_t i = (size_t)0U; i < (size_t)6U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    memcpy(commitment.data, repeat_expression6, (size_t)6U * sizeof (Eurydice_arr_a4));
    libcrux_ml_dsa_sample_sample_mask_vector_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      &mask_seed,
      &domain_separator_for_mask,
      Eurydice_array_to_slice_mut_711(&mask));
    Eurydice_arr_a3 a_x_mask;
    Eurydice_arr_a4 repeat_expression[6U];
    for (size_t i = (size_t)0U; i < (size_t)6U; i++)
    {
      repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    memcpy(a_x_mask.data, repeat_expression, (size_t)6U * sizeof (Eurydice_arr_a4));
    Eurydice_arr_b0
    mask_ntt =
      core_array__core__clone__Clone_for__Array_T__N___clone((size_t)5U,
        &mask,
        Eurydice_arr_a4,
        Eurydice_arr_b0);
    for (size_t i = (size_t)0U; i < (size_t)5U; i++)
    {
      size_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&mask_ntt.data[i0]);
    }
    libcrux_ml_dsa_matrix_compute_matrix_x_mask_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      Eurydice_array_to_slice_shared_712(&matrix),
      Eurydice_array_to_slice_shared_71(&mask_ntt),
      Eurydice_array_to_slice_mut_712(&a_x_mask));
    libcrux_ml_dsa_arithmetic_decompose_vector_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
      Eurydice_array_to_slice_shared_711(&a_x_mask),
      Eurydice_array_to_slice_mut_712(&w0),
      Eurydice_array_to_slice_mut_712(&commitment));
    Eurydice_arr_5f commitment_hash_candidate = { { 0U } };
    Eurydice_arr_56 commitment_serialized = { { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_SIZE,
      Eurydice_array_to_slice_shared_711(&commitment),
      Eurydice_array_to_slice_mut_ee(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_to_slice_shared_d8(&message_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_to_slice_shared_ee(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_to_slice_mut_95(&commitment_hash_candidate));
    Eurydice_arr_a4 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_95(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_b0
    challenge_times_s1 =
      core_array__core__clone__Clone_for__Array_T__N___clone((size_t)5U,
        &s1_as_ntt,
        Eurydice_arr_a4,
        Eurydice_arr_b0);
    Eurydice_arr_a3
    challenge_times_s2 =
      core_array__core__clone__Clone_for__Array_T__N___clone((size_t)6U,
        &s2_as_ntt,
        Eurydice_arr_a4,
        Eurydice_arr_a3);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_711(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_712(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      Eurydice_array_to_slice_mut_711(&mask),
      Eurydice_array_to_slice_shared_71(&challenge_times_s1));
    libcrux_ml_dsa_matrix_subtract_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      Eurydice_array_to_slice_mut_712(&w0),
      Eurydice_array_to_slice_shared_711(&challenge_times_s2));
    if
    (
      !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_71(&mask),
        ((int32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      if
      (
        !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_711(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
      )
      {
        Eurydice_arr_a3
        challenge_times_t0 =
          core_array__core__clone__Clone_for__Array_T__N___clone((size_t)6U,
            &t0_as_ntt,
            Eurydice_arr_a4,
            Eurydice_arr_a3);
        libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_712(&challenge_times_t0),
          &verifier_challenge);
        if
        (
          !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_711(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2)
        )
        {
          libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
            Eurydice_array_to_slice_mut_712(&w0),
            Eurydice_array_to_slice_shared_711(&challenge_times_t0));
          Eurydice_arr_b5
          hint_candidate =
            { { { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } } } };
          size_t
          ones_in_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_to_slice_shared_711(&w0),
              Eurydice_array_to_slice_shared_711(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
              Eurydice_array_to_slice_mut_6d(&hint_candidate));
          if (!(ones_in_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 = ((Option_a6){ Some, commitment_hash_candidate });
            signer_response0 = ((Option_c8){ Some, mask });
            hint0 = ((Option_cb){ Some, hint_candidate });
          }
        }
      }
    }
  }
  Result_53 uu____5;
  if (commitment_hash0.tag == None)
  {
    uu____5 = ((Result_53){ Err, libcrux_ml_dsa_types_SigningError_RejectionSamplingError });
  }
  else
  {
    Eurydice_arr_5f commitment_hash = commitment_hash0.f0;
    Eurydice_arr_5f commitment_hash1 = commitment_hash;
    if (signer_response0.tag == None)
    {
      uu____5 = ((Result_53){ Err, libcrux_ml_dsa_types_SigningError_RejectionSamplingError });
    }
    else
    {
      Eurydice_arr_b0 signer_response = signer_response0.f0;
      Eurydice_arr_b0 signer_response1 = signer_response;
      if (!(hint0.tag == None))
      {
        Eurydice_arr_b5 hint = hint0.f0;
        Eurydice_arr_b5 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_to_slice_shared_95(&commitment_hash1),
          Eurydice_array_to_slice_shared_71(&signer_response1),
          Eurydice_array_to_slice_shared_6d(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_SIZE,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_SIZE,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT,
          Eurydice_array_to_slice_mut_ee0(signature));
        return ((Result_53){ Ok });
      }
      uu____5 = ((Result_53){ Err, libcrux_ml_dsa_types_SigningError_RejectionSamplingError });
    }
  }
  return uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE Result_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(
  Eurydice_borrow_slice_u8 signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness,
  Eurydice_arr_96 *signature
)
{
  Result_a8 uu____0 = libcrux_ml_dsa_pre_hash_new_88(context, ((Option_b5){ None }));
  if (!(uu____0.tag == Ok))
  {
    return ((Result_53){ Err, libcrux_ml_dsa_types_SigningError_ContextTooLongError });
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_internal_5a(signing_key,
      message,
      ((Option_84){ Some, domain_separation_context }),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
static KRML_MUSTINLINE Result_97
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(
  Eurydice_borrow_slice_u8 signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness
)
{
  Eurydice_arr_96 signature = libcrux_ml_dsa_types_zero_c5_fa();
  Result_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(signing_key,
      message,
      context,
      randomness,
      &signature);
  Result_97 uu____1;
  if (uu____0.tag == Ok)
  {
    uu____1 = (Result_97){ .tag = Ok, .val = { .case_Ok = signature } };
  }
  else
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 = (Result_97){ .tag = Err, .val = { .case_Err = e } };
  }
  return uu____1;
}

/**
 Sign.
*/
static inline Result_97
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(
  const Eurydice_arr_d10 *signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(Eurydice_array_to_slice_shared_ef(signing_key),
      message,
      context,
      randomness);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
static inline Result_97
libcrux_ml_dsa_ml_dsa_65_portable_sign(
  const Eurydice_arr_d10 *signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(libcrux_ml_dsa_types_as_ref_9b_09(signing_key),
      message,
      context,
      randomness);
}

/**
 Sign.
*/
static inline Result_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(
  const Eurydice_arr_d10 *signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness,
  Eurydice_arr_96 *signature
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(Eurydice_array_to_slice_shared_ef(signing_key),
      message,
      context,
      randomness,
      signature);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
static inline Result_53
libcrux_ml_dsa_ml_dsa_65_portable_sign_mut(
  const Eurydice_arr_d10 *signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness,
  Eurydice_arr_96 *signature
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(signing_key,
      message,
      context,
      randomness,
      signature);
}

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
/**
A monomorphic instance of libcrux_ml_dsa.pre_hash.hash_30
with types libcrux_ml_dsa_hash_functions_portable_Shake128
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_pre_hash_hash_30_83(
  Eurydice_borrow_slice_u8 message,
  Eurydice_mut_borrow_slice_u8 output
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128_7b(message, output);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
static KRML_MUSTINLINE Result_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(
  Eurydice_borrow_slice_u8 signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_buffer,
  Eurydice_arr_600 randomness,
  Eurydice_arr_96 *signature
)
{
  if (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_buffer);
    Result_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        ((Option_b5){ Some, libcrux_ml_dsa_pre_hash_oid_30() }));
    if (!(uu____0.tag == Ok))
    {
      return ((Result_53){ Err, libcrux_ml_dsa_types_SigningError_ContextTooLongError });
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    return
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_internal_5a(signing_key,
        ((Eurydice_borrow_slice_u8){ pre_hash_buffer.ptr, pre_hash_buffer.meta }),
        ((Option_84){ Some, domain_separation_context }),
        randomness,
        signature);
  }
  return ((Result_53){ Err, libcrux_ml_dsa_types_SigningError_ContextTooLongError });
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
static KRML_MUSTINLINE Result_97
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(
  Eurydice_borrow_slice_u8 signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_buffer,
  Eurydice_arr_600 randomness
)
{
  Eurydice_arr_96 signature = libcrux_ml_dsa_types_zero_c5_fa();
  Result_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(signing_key,
      message,
      context,
      pre_hash_buffer,
      randomness,
      &signature);
  Result_97 uu____1;
  if (uu____0.tag == Ok)
  {
    uu____1 = (Result_97){ .tag = Ok, .val = { .case_Ok = signature } };
  }
  else
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 = (Result_97){ .tag = Err, .val = { .case_Err = e } };
  }
  return uu____1;
}

/**
 Sign (pre-hashed).
*/
static inline Result_97
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(
  const Eurydice_arr_d10 *signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_buffer,
  Eurydice_arr_600 randomness
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(Eurydice_array_to_slice_shared_ef(signing_key),
      message,
      context,
      pre_hash_buffer,
      randomness);
}

/**
 Generate a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
static inline Result_97
libcrux_ml_dsa_ml_dsa_65_portable_sign_pre_hashed_shake128(
  const Eurydice_arr_d10 *signing_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_600 randomness
)
{
  Eurydice_arr_600 pre_hash_buffer = { { 0U } };
  const Eurydice_arr_d10 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_09(signing_key);
  return
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(uu____0,
      message,
      context,
      Eurydice_array_to_slice_mut_6e(&pre_hash_buffer),
      randomness);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static inline void
libcrux_ml_dsa_encoding_t1_deserialize_37(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a4 *result
)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_t1_deserialize_65(Eurydice_slice_subslice_shared_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_WINDOW,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_WINDOW
          }
        )),
      &result->data[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_encoding_verification_key_deserialize_37(
  size_t rows_in_a,
  size_t verification_key_size,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_dst_ref_mut_e7 t1
)
{
  for (size_t i = (size_t)0U; i < rows_in_a; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_encoding_t1_deserialize_37(Eurydice_slice_subslice_shared_7e(serialized,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1S_SIZE,
            (i0 + (size_t)1U) * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1S_SIZE
          }
        )),
      &t1.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE Result_41
libcrux_ml_dsa_encoding_signature_deserialize_37(
  size_t columns_in_a,
  size_t rows_in_a,
  size_t commitment_hash_size,
  size_t gamma1_exponent,
  size_t gamma1_ring_element_size,
  size_t max_ones_in_hint,
  size_t signature_size,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_mut_borrow_slice_u8 out_commitment_hash,
  Eurydice_dst_ref_mut_e7 out_signer_response,
  Eurydice_dst_ref_mut_22 out_hint
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(serialized,
      commitment_hash_size,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 commitment_hash = uu____0.fst;
  Eurydice_borrow_slice_u8 rest_of_serialized = uu____0.snd;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(out_commitment_hash,
      ((core_ops_range_Range_08){ (size_t)0U, commitment_hash_size })),
    commitment_hash,
    uint8_t);
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(rest_of_serialized,
      gamma1_ring_element_size * columns_in_a,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 signer_response_serialized = uu____1.fst;
  Eurydice_borrow_slice_u8 hint_serialized = uu____1.snd;
  for (size_t i = (size_t)0U; i < columns_in_a; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
      Eurydice_slice_subslice_shared_7e(signer_response_serialized,
        (
          (core_ops_range_Range_08){
            i0 * gamma1_ring_element_size,
            (i0 + (size_t)1U) * gamma1_ring_element_size
          }
        )),
      &out_signer_response.ptr[i0]);
  }
  size_t previous_true_hints_seen = (size_t)0U;
  bool malformed_hint = false;
  for (size_t i0 = (size_t)0U; i0 < rows_in_a; i0++)
  {
    size_t i1 = i0;
    size_t current_true_hints_seen = (size_t)hint_serialized.ptr[max_ones_in_hint + i1];
    if (current_true_hints_seen < previous_true_hints_seen)
    {
      malformed_hint = true;
    }
    else if (current_true_hints_seen > max_ones_in_hint)
    {
      malformed_hint = true;
    }
    else
    {
      for (size_t i = previous_true_hints_seen; i < current_true_hints_seen; i++)
      {
        size_t j = i;
        if (j > previous_true_hints_seen)
        {
          if (hint_serialized.ptr[j] <= hint_serialized.ptr[j - (size_t)1U])
          {
            malformed_hint = true;
            break;
          }
        }
        libcrux_ml_dsa_encoding_signature_set_hint(out_hint, i1, (size_t)hint_serialized.ptr[j]);
      }
      if (!malformed_hint)
      {
        previous_true_hints_seen = current_true_hints_seen;
        continue;
      }
    }
    break;
  }
  for (size_t i = previous_true_hints_seen; i < max_ones_in_hint; i++)
  {
    size_t j = i;
    if (!(hint_serialized.ptr[j] != 0U))
    {
      continue;
    }
    malformed_hint = true;
    break;
  }
  Result_41 uu____2;
  if (malformed_hint)
  {
    uu____2 = ((Result_41){ Err, libcrux_ml_dsa_types_VerificationError_MalformedHintError });
  }
  else
  {
    uu____2 = ((Result_41){ Ok });
  }
  return uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.arithmetic.shift_left_then_reduce
with const generics
- SHIFT_BY= 13
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_simd_portable_arithmetic_shift_left_then_reduce_84(Eurydice_arr_d4 *simd_unit)
{
  for (size_t i = (size_t)0U; i < (size_t)8U; i++)
  {
    size_t i0 = i;
    simd_unit->data[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_reduce_element(simd_unit->data[i0] <<
          (uint32_t)(int32_t)13);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.shift_left_then_reduce_65
with const generics
- SHIFT_BY= 13
*/
static inline void
libcrux_ml_dsa_simd_portable_shift_left_then_reduce_65_84(Eurydice_arr_d4 *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_shift_left_then_reduce_84(simd_unit);
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.shift_left_then_reduce
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- SHIFT_BY= 13
*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_arithmetic_shift_left_then_reduce_68(Eurydice_arr_a4 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)32U; i++)
  {
    size_t i0 = i;
    libcrux_ml_dsa_simd_portable_shift_left_then_reduce_65_84(&re->data[i0]);
  }
}

/**
 Compute InvertNTT(Â ◦ ẑ - ĉ ◦ NTT(t₁2ᵈ))
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_w_approx
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_matrix_compute_w_approx_37(
  size_t rows_in_a,
  size_t columns_in_a,
  Eurydice_dst_ref_shared_e7 matrix,
  Eurydice_dst_ref_shared_e7 signer_response,
  const Eurydice_arr_a4 *verifier_challenge_as_ntt,
  Eurydice_dst_ref_mut_e7 t1
)
{
  for (size_t i0 = (size_t)0U; i0 < rows_in_a; i0++)
  {
    size_t i1 = i0;
    Eurydice_arr_a4 inner_result = libcrux_ml_dsa_polynomial_zero_ff_37();
    for (size_t i = (size_t)0U; i < columns_in_a; i++)
    {
      size_t j = i;
      Eurydice_arr_a4 product = matrix.ptr[i1 * columns_in_a + j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&product, &signer_response.ptr[j]);
      libcrux_ml_dsa_polynomial_add_ff_37(&inner_result, &product);
    }
    libcrux_ml_dsa_arithmetic_shift_left_then_reduce_68(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&t1.ptr[i1], verifier_challenge_as_ntt);
    libcrux_ml_dsa_polynomial_subtract_ff_37(&inner_result, &t1.ptr[i1]);
    t1.ptr[i1] = inner_result;
    libcrux_ml_dsa_ntt_reduce_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&t1.ptr[i1]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.use_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_dsa_arithmetic_use_hint_37(
  int32_t gamma2,
  Eurydice_dst_ref_shared_22 hint,
  Eurydice_dst_ref_mut_e7 re_vector
)
{
  for (size_t i0 = (size_t)0U; i0 < re_vector.meta; i0++)
  {
    size_t i1 = i0;
    Eurydice_arr_a4 tmp = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_200(&hint.ptr[i1]),
      &tmp);
    for (size_t i = (size_t)0U; i < (size_t)32U; i++)
    {
      size_t j = i;
      libcrux_ml_dsa_simd_portable_use_hint_65(gamma2, &re_vector.ptr[i1].data[j], &tmp.data[j]);
    }
    re_vector.ptr[i1] = tmp;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
static KRML_MUSTINLINE Result_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_internal_5a(
  const Eurydice_arr_4a *verification_key,
  Eurydice_borrow_slice_u8 message,
  Option_84 domain_separation_context,
  const Eurydice_arr_96 *signature_serialized
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_5b(verification_key),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_a3 t1;
  Eurydice_arr_a4 repeat_expression0[6U];
  for (size_t i = (size_t)0U; i < (size_t)6U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(t1.data, repeat_expression0, (size_t)6U * sizeof (Eurydice_arr_a4));
  libcrux_ml_dsa_encoding_verification_key_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_KEY_SIZE,
    t1_serialized,
    Eurydice_array_to_slice_mut_712(&t1));
  Eurydice_arr_5f deserialized_commitment_hash = { { 0U } };
  Eurydice_arr_b0 deserialized_signer_response;
  Eurydice_arr_a4 repeat_expression1[5U];
  for (size_t i = (size_t)0U; i < (size_t)5U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  memcpy(deserialized_signer_response.data,
    repeat_expression1,
    (size_t)5U * sizeof (Eurydice_arr_a4));
  Eurydice_arr_b5
  deserialized_hint =
    { { { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } }, { { 0U } } } };
  Result_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_SIZE,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_SIZE,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_SIZE,
      Eurydice_array_to_slice_shared_ee0(signature_serialized),
      Eurydice_array_to_slice_mut_95(&deserialized_commitment_hash),
      Eurydice_array_to_slice_mut_711(&deserialized_signer_response),
      Eurydice_array_to_slice_mut_6d(&deserialized_hint));
  Result_41 uu____2;
  if (uu____1.tag == Ok)
  {
    if
    (
      libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_71(&deserialized_signer_response),
        ((int32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      uu____2 =
        ((Result_41){ Err, libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError });
    }
    else
    {
      Eurydice_arr_a1 matrix;
      Eurydice_arr_a4 repeat_expression[30U];
      for (size_t i = (size_t)0U; i < (size_t)30U; i++)
      {
        repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      memcpy(matrix.data, repeat_expression, (size_t)30U * sizeof (Eurydice_arr_a4));
      libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
        seed_for_a,
        Eurydice_array_to_slice_mut_710(&matrix));
      Eurydice_arr_060 verification_key_hash = { { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_24(Eurydice_array_to_slice_shared_5b(verification_key),
        &verification_key_hash);
      Eurydice_arr_060 message_representative = { { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(Eurydice_array_to_slice_shared_d8(&verification_key_hash),
        &domain_separation_context,
        message,
        &message_representative);
      Eurydice_arr_a4 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_95(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      for (size_t i = (size_t)0U; i < (size_t)5U; i++)
      {
        size_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.data[i0]);
      }
      libcrux_ml_dsa_matrix_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
        Eurydice_array_to_slice_shared_712(&matrix),
        Eurydice_array_to_slice_shared_71(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_to_slice_mut_712(&t1));
      Eurydice_arr_5f recomputed_commitment_hash = { { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
        Eurydice_array_to_slice_shared_6d(&deserialized_hint),
        Eurydice_array_to_slice_mut_712(&t1));
      Eurydice_arr_56 commitment_serialized = { { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_SIZE,
        Eurydice_array_to_slice_shared_711(&t1),
        Eurydice_array_to_slice_mut_ee(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_e2
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_to_slice_shared_d8(&message_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_to_slice_shared_ee(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_to_slice_mut_95(&recomputed_commitment_hash));
      if
      (
        Eurydice_array_eq((size_t)48U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = ((Result_41){ Ok });
      }
      else
      {
        uu____2 =
          ((Result_41){ Err, libcrux_ml_dsa_types_VerificationError_CommitmentHashesDontMatchError });
      }
    }
  }
  else
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = ((Result_41){ Err, e });
  }
  return uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
static KRML_MUSTINLINE Result_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(
  const Eurydice_arr_4a *verification_key_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  const Eurydice_arr_96 *signature_serialized
)
{
  Result_a8 uu____0 = libcrux_ml_dsa_pre_hash_new_88(context, ((Option_b5){ None }));
  if (!(uu____0.tag == Ok))
  {
    return
      ((Result_41){ Err, libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError });
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_internal_5a(verification_key_serialized,
      message,
      ((Option_84){ Some, domain_separation_context }),
      signature_serialized);
}

/**
 Verify.
*/
static inline Result_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(
  const Eurydice_arr_4a *verification_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  const Eurydice_arr_96 *signature
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(verification_key,
      message,
      context,
      signature);
}

/**
 Verify an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
static inline Result_41
libcrux_ml_dsa_ml_dsa_65_portable_verify(
  const Eurydice_arr_4a *verification_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  const Eurydice_arr_96 *signature
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(libcrux_ml_dsa_types_as_ref_7f_97(verification_key),
      message,
      context,
      libcrux_ml_dsa_types_as_ref_c5_fa(signature));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
static KRML_MUSTINLINE Result_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(
  const Eurydice_arr_4a *verification_key_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_buffer,
  const Eurydice_arr_96 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_buffer);
  Result_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      ((Option_b5){ Some, libcrux_ml_dsa_pre_hash_oid_30() }));
  if (!(uu____0.tag == Ok))
  {
    return
      ((Result_41){ Err, libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError });
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_internal_5a(verification_key_serialized,
      ((Eurydice_borrow_slice_u8){ pre_hash_buffer.ptr, pre_hash_buffer.meta }),
      ((Option_84){ Some, domain_separation_context }),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
static inline Result_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(
  const Eurydice_arr_4a *verification_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_buffer,
  const Eurydice_arr_96 *signature
)
{
  return
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(verification_key,
      message,
      context,
      pre_hash_buffer,
      signature);
}

/**
 Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
static inline Result_41
libcrux_ml_dsa_ml_dsa_65_portable_verify_pre_hashed_shake128(
  const Eurydice_arr_4a *verification_key,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  const Eurydice_arr_96 *signature
)
{
  Eurydice_arr_600 pre_hash_buffer = { { 0U } };
  const Eurydice_arr_4a *uu____0 = libcrux_ml_dsa_types_as_ref_7f_97(verification_key);
  Eurydice_borrow_slice_u8 uu____1 = message;
  Eurydice_borrow_slice_u8 uu____2 = context;
  Eurydice_mut_borrow_slice_u8 uu____3 = Eurydice_array_to_slice_mut_6e(&pre_hash_buffer);
  return
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_fa(signature));
}

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_VECTOR_SIZE (libcrux_ml_dsa_constants_commitment_vector_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A))

typedef libcrux_ml_dsa_types_MLDSAKeyPair_06
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65KeyPair;

typedef Eurydice_arr_96 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature;

typedef Eurydice_arr_d10 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65SigningKey;

typedef Eurydice_arr_4a libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65VerificationKey;

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ROW_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A)

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ROW_X_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A)

#define LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNING_KEY_SIZE (libcrux_ml_dsa_constants_signing_key_size(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_SIZE))

#define LIBCRUX_ML_DSA_PRE_HASH_PRE_HASH_OID_LEN ((size_t)11U)

typedef Eurydice_arr_cb libcrux_ml_dsa_pre_hash_PreHashOID;

typedef Result_a8 libcrux_ml_dsa_pre_hash_PreHashResult;

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::SigningError}
*/
static inline libcrux_ml_dsa_types_SigningError
libcrux_ml_dsa_pre_hash_from_96(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  return libcrux_ml_dsa_types_SigningError_ContextTooLongError;
}

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::VerificationError}
*/
static inline libcrux_ml_dsa_types_VerificationError
libcrux_ml_dsa_pre_hash_from_bf(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  return libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError;
}

typedef int32_t libcrux_ml_dsa_simd_portable_vector_type_FieldElement;

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
static inline Eurydice_arr_d4
libcrux_ml_dsa_simd_portable_vector_type_clone_a5(const Eurydice_arr_d4 *self)
{
  return self[0U];
}

typedef int32_t libcrux_ml_dsa_simd_traits_FieldElementTimesMontgomeryR;


#define libcrux_mldsa65_portable_H_DEFINED
#endif /* libcrux_mldsa65_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mlkem_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_mlkem_core_H
#define libcrux_mlkem_core_H





#define LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE ((size_t)32U)

#define LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_COEFFICIENT ((size_t)12U)

#define LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT ((size_t)256U)

#define LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (size_t)12U)

#define LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT / (size_t)8U)

#define LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE ((size_t)32U)

#define LIBCRUX_ML_KEM_CONSTANTS_G_DIGEST_SIZE ((size_t)64U)

#define LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE ((size_t)32U)

/**
 K * BITS_PER_RING_ELEMENT / 8

 [eurydice] Note that we can't use const generics here because that breaks
            C extraction with eurydice.
*/
static inline size_t libcrux_ml_kem_constants_ranked_bytes_per_ring_element(size_t rank)
{
  return rank * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT / (size_t)8U;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint8_t

*/
static KRML_MUSTINLINE uint8_t libcrux_secrets_int_public_integers_classify_27_90(uint8_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int16_t

*/
static KRML_MUSTINLINE int16_t
libcrux_secrets_int_public_integers_declassify_d8_39(int16_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
static KRML_MUSTINLINE uint8_t libcrux_secrets_int_as_u8_f5(int16_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_90((uint8_t)libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int16_t

*/
static KRML_MUSTINLINE int16_t libcrux_secrets_int_public_integers_classify_27_39(int16_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint8_t

*/
static KRML_MUSTINLINE uint8_t
libcrux_secrets_int_public_integers_declassify_d8_90(uint8_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u8}
*/
static KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_59(uint8_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)libcrux_secrets_int_public_integers_declassify_d8_90(self));
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int32_t

*/
static KRML_MUSTINLINE int32_t libcrux_secrets_int_public_integers_classify_27_a8(int32_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
static KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_f5(int16_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_a8((int32_t)libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int32_t

*/
static KRML_MUSTINLINE int32_t
libcrux_secrets_int_public_integers_declassify_d8_a8(int32_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i32}
*/
static KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_36(int32_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)libcrux_secrets_int_public_integers_declassify_d8_a8(self));
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint32_t

*/
static KRML_MUSTINLINE uint32_t
libcrux_secrets_int_public_integers_declassify_d8_df(uint32_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
static KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_b8(uint32_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_a8((int32_t)libcrux_secrets_int_public_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint16_t

*/
static KRML_MUSTINLINE uint16_t
libcrux_secrets_int_public_integers_classify_27_de(uint16_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
static KRML_MUSTINLINE uint16_t libcrux_secrets_int_as_u16_f5(int16_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_de((uint16_t)libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint16_t

*/
static KRML_MUSTINLINE uint16_t
libcrux_secrets_int_public_integers_declassify_d8_de(uint16_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
static KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_ca(uint16_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)libcrux_secrets_int_public_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint64_t

*/
static KRML_MUSTINLINE uint64_t
libcrux_secrets_int_public_integers_classify_27_49(uint64_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
static KRML_MUSTINLINE uint64_t libcrux_secrets_int_as_u64_ca(uint16_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_49((uint64_t)libcrux_secrets_int_public_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint32_t

*/
static KRML_MUSTINLINE uint32_t
libcrux_secrets_int_public_integers_classify_27_df(uint32_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint64_t

*/
static KRML_MUSTINLINE uint64_t
libcrux_secrets_int_public_integers_declassify_d8_49(uint64_t self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u64}
*/
static KRML_MUSTINLINE uint32_t libcrux_secrets_int_as_u32_a3(uint64_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_df((uint32_t)libcrux_secrets_int_public_integers_declassify_d8_49(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
static KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_b8(uint32_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)libcrux_secrets_int_public_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
static KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_f5(int16_t self)
{
  return
    libcrux_secrets_int_public_integers_classify_27_39(libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
A monomorphic instance of K.
with types Eurydice_arr_60, Eurydice_arr_74

*/
typedef struct tuple_f4_s
{
  Eurydice_arr_60 fst;
  Eurydice_arr_74 snd;
}
tuple_f4;

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 32
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_utils_into_padded_array_9e(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_600 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_364(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  return out;
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.default_d3
with const generics
- SIZE= 2400
*/
static inline Eurydice_arr_ea libcrux_ml_kem_types_default_d3_28(void)
{
  return ((Eurydice_arr_ea){ { 0U } });
}

/**
This function found in impl {core::convert::From<@Array<u8, SIZE>> for libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_fd
with const generics
- SIZE= 1184
*/
static inline Eurydice_arr_74 libcrux_ml_kem_types_from_fd_d0(Eurydice_arr_74 value)
{
  return value;
}

typedef struct libcrux_ml_kem_mlkem768_MlKem768KeyPair_s
{
  Eurydice_arr_ea sk;
  Eurydice_arr_74 pk;
}
libcrux_ml_kem_mlkem768_MlKem768KeyPair;

/**
This function found in impl {libcrux_ml_kem::types::MlKemKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_17
with const generics
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
static inline libcrux_ml_kem_mlkem768_MlKem768KeyPair
libcrux_ml_kem_types_from_17_74(Eurydice_arr_ea sk, Eurydice_arr_74 pk)
{
  return ((libcrux_ml_kem_mlkem768_MlKem768KeyPair){ sk, pk });
}

/**
This function found in impl {core::convert::From<@Array<u8, SIZE>> for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_77
with const generics
- SIZE= 2400
*/
static inline Eurydice_arr_ea libcrux_ml_kem_types_from_77_28(Eurydice_arr_ea value)
{
  return value;
}

/**
A monomorphic instance of K.
with types libcrux_ml_kem_mlkem768_MlKem768Ciphertext, Eurydice_arr_600

*/
typedef struct tuple_38_s
{
  Eurydice_arr_2c fst;
  Eurydice_arr_600 snd;
}
tuple_38;

/**
This function found in impl {core::convert::From<@Array<u8, SIZE>> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_e0
with const generics
- SIZE= 1088
*/
static inline Eurydice_arr_2c libcrux_ml_kem_types_from_e0_80(Eurydice_arr_2c value)
{
  return value;
}

/**
This function found in impl {libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_e6
with const generics
- SIZE= 1184
*/
static inline const
Eurydice_arr_74
*libcrux_ml_kem_types_as_slice_e6_d0(const Eurydice_arr_74 *self)
{
  return self;
}

/**
This function found in impl {libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_a9
with const generics
- SIZE= 1088
*/
static inline const
Eurydice_arr_2c
*libcrux_ml_kem_types_as_slice_a9_80(const Eurydice_arr_2c *self)
{
  return self;
}

/**
A monomorphic instance of libcrux_ml_kem.utils.prf_input_inc
with const generics
- K= 3
*/
static KRML_MUSTINLINE uint8_t
libcrux_ml_kem_utils_prf_input_inc_e0(Eurydice_arr_b1 *prf_inputs, uint8_t domain_separator)
{
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    prf_inputs->data[i0].data[32U] = domain_separator;
    domain_separator = (uint32_t)domain_separator + 1U;
  }
  return domain_separator;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 33
*/
static KRML_MUSTINLINE Eurydice_arr_3e0
libcrux_ml_kem_utils_into_padded_array_c8(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_3e0 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3612(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  return out;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 34
*/
static KRML_MUSTINLINE Eurydice_arr_48
libcrux_ml_kem_utils_into_padded_array_b6(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_48 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_366(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  return out;
}

/**
This function found in impl {core::convert::AsRef<@Slice<u8>> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_d3
with const generics
- SIZE= 1088
*/
static inline Eurydice_borrow_slice_u8
libcrux_ml_kem_types_as_ref_d3_80(const Eurydice_arr_2c *self)
{
  return Eurydice_array_to_slice_shared_42(self);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1120
*/
static KRML_MUSTINLINE Eurydice_arr_480
libcrux_ml_kem_utils_into_padded_array_15(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_480 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3611(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  return out;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 64
*/
static KRML_MUSTINLINE Eurydice_arr_060
libcrux_ml_kem_utils_into_padded_array_24(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_060 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3610(&out,
      ((core_ops_range_Range_08){ (size_t)0U, slice.meta })),
    slice,
    uint8_t);
  return out;
}

typedef struct Eurydice_borrow_slice_u8_x4_s
{
  Eurydice_borrow_slice_u8 fst;
  Eurydice_borrow_slice_u8 snd;
  Eurydice_borrow_slice_u8 thd;
  Eurydice_borrow_slice_u8 f3;
}
Eurydice_borrow_slice_u8_x4;

/**
 Unpack an incoming private key into it's different parts.

 We have this here in types to extract into a common core for C.
*/
/**
A monomorphic instance of libcrux_ml_kem.types.unpack_private_key
with const generics
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
static inline Eurydice_borrow_slice_u8_x4
libcrux_ml_kem_types_unpack_private_key_b4(Eurydice_borrow_slice_u8 private_key)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(private_key,
      (size_t)1152U,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 ind_cpa_secret_key = uu____0.fst;
  Eurydice_borrow_slice_u8 secret_key0 = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(secret_key0,
      (size_t)1184U,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 ind_cpa_public_key = uu____1.fst;
  Eurydice_borrow_slice_u8 secret_key = uu____1.snd;
  Eurydice_borrow_slice_u8_x2
  uu____2 =
    Eurydice_slice_split_at(secret_key,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 ind_cpa_public_key_hash = uu____2.fst;
  Eurydice_borrow_slice_u8 implicit_rejection_value = uu____2.snd;
  return
    (
      (Eurydice_borrow_slice_u8_x4){
        ind_cpa_secret_key,
        ind_cpa_public_key,
        ind_cpa_public_key_hash,
        implicit_rejection_value
      }
    );
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$24size_t]]

*/
static KRML_MUSTINLINE Eurydice_arr_6d
libcrux_secrets_int_public_integers_declassify_d8_bd(Eurydice_arr_6d self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$20size_t]]

*/
static KRML_MUSTINLINE Eurydice_arr_dc
libcrux_secrets_int_public_integers_declassify_d8_89(Eurydice_arr_dc self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$8size_t]]

*/
static KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_secrets_int_public_integers_declassify_d8_36(Eurydice_array_u8x8 self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$2size_t]]

*/
static KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_secrets_int_public_integers_declassify_d8_ee0(Eurydice_array_u8x2 self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types Eurydice_arr int16_t[[$16size_t]]

*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_secrets_int_public_integers_classify_27_3a(Eurydice_arr_e2 self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a (@Slice<T>)> for &'a (@Slice<T>)}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_9b
with types uint8_t

*/
static KRML_MUSTINLINE Eurydice_borrow_slice_u8
libcrux_secrets_int_classify_public_classify_ref_9b_90(Eurydice_borrow_slice_u8 self)
{
  return self;
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a (@Slice<T>)> for &'a (@Slice<T>)}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_9b
with types int16_t

*/
static KRML_MUSTINLINE Eurydice_borrow_slice_i16
libcrux_secrets_int_classify_public_classify_ref_9b_39(Eurydice_borrow_slice_i16 self)
{
  return self;
}


#define libcrux_mlkem_core_H_DEFINED
#endif /* libcrux_mlkem_core_H */

/* from libcrux/combined_extraction/generated/libcrux_ct_ops.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_ct_ops_H
#define libcrux_ct_ops_H





/**
 Return 1 if `value` is not zero and 0 otherwise.
*/
static KRML_NOINLINE uint8_t libcrux_ml_kem_constant_time_ops_inz(uint8_t value)
{
  uint16_t value0 = (uint16_t)value;
  uint8_t result = (uint8_t)((uint32_t)core_num__u16__wrapping_add(~value0, 1U) >> 8U);
  return (uint32_t)result & 1U;
}

static KRML_NOINLINE uint8_t libcrux_ml_kem_constant_time_ops_is_non_zero(uint8_t value)
{
  return libcrux_ml_kem_constant_time_ops_inz(value);
}

/**
 Return 1 if the bytes of `lhs` and `rhs` do not exactly
 match and 0 otherwise.
*/
static KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_time_ops_compare(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs
)
{
  uint8_t r = 0U;
  for (size_t i = (size_t)0U; i < lhs.meta; i++)
  {
    size_t i0 = i;
    uint8_t nr = (uint32_t)r | ((uint32_t)lhs.ptr[i0] ^ (uint32_t)rhs.ptr[i0]);
    r = nr;
  }
  return libcrux_ml_kem_constant_time_ops_is_non_zero(r);
}

static KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_time_ops_compare_ciphertexts_in_constant_time(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs
)
{
  return libcrux_ml_kem_constant_time_ops_compare(lhs, rhs);
}

/**
 If `selector` is not zero, return the bytes in `rhs`; return the bytes in
 `lhs` otherwise.
*/
static KRML_NOINLINE Eurydice_arr_600
libcrux_ml_kem_constant_time_ops_select_ct(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs,
  uint8_t selector
)
{
  uint8_t
  mask = core_num__u8__wrapping_sub(libcrux_ml_kem_constant_time_ops_is_non_zero(selector), 1U);
  Eurydice_arr_600 out = { { 0U } };
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE; i++)
  {
    size_t i0 = i;
    uint8_t
    outi = ((uint32_t)lhs.ptr[i0] & (uint32_t)mask) | ((uint32_t)rhs.ptr[i0] & (uint32_t)~mask);
    out.data[i0] = outi;
  }
  return out;
}

static KRML_NOINLINE Eurydice_arr_600
libcrux_ml_kem_constant_time_ops_select_shared_secret_in_constant_time(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs,
  uint8_t selector
)
{
  return libcrux_ml_kem_constant_time_ops_select_ct(lhs, rhs, selector);
}

static KRML_NOINLINE Eurydice_arr_600
libcrux_ml_kem_constant_time_ops_compare_ciphertexts_select_shared_secret_in_constant_time(
  Eurydice_borrow_slice_u8 lhs_c,
  Eurydice_borrow_slice_u8 rhs_c,
  Eurydice_borrow_slice_u8 lhs_s,
  Eurydice_borrow_slice_u8 rhs_s
)
{
  uint8_t
  selector = libcrux_ml_kem_constant_time_ops_compare_ciphertexts_in_constant_time(lhs_c, rhs_c);
  return
    libcrux_ml_kem_constant_time_ops_select_shared_secret_in_constant_time(lhs_s,
      rhs_s,
      selector);
}


#define libcrux_ct_ops_H_DEFINED
#endif /* libcrux_ct_ops_H */

/* from libcrux/combined_extraction/generated/libcrux_mlkem768_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 377317d6b25702c46ffff072fa00a3e32095e46f
 * Eurydice: b227478b67c6a6e2ff611f978f10d6b7f26472ac
 * Karamel: 4e64d915da3c172d1dfad805b8e1a46beff938bc
 * F*: 89901492c020c74b82d811d27f3149c222d9b8b5
 * Libcrux: 242687bfb0fbc29107b95a0f3e72202e9978064b
 */


#ifndef libcrux_mlkem768_portable_H
#define libcrux_mlkem768_portable_H





static inline Eurydice_arr_060
libcrux_ml_kem_hash_functions_portable_G(Eurydice_borrow_slice_u8 input)
{
  Eurydice_arr_060 digest = { { 0U } };
  libcrux_sha3_portable_sha512(Eurydice_array_to_slice_mut_d8(&digest), input);
  return digest;
}

static inline Eurydice_arr_600
libcrux_ml_kem_hash_functions_portable_H(Eurydice_borrow_slice_u8 input)
{
  Eurydice_arr_600 digest = { { 0U } };
  libcrux_sha3_portable_sha256(Eurydice_array_to_slice_mut_6e(&digest), input);
  return digest;
}

#define LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R (((Eurydice_arr_49){ { (int16_t)-1044, (int16_t)-758, (int16_t)-359, (int16_t)-1517, (int16_t)1493, (int16_t)1422, (int16_t)287, (int16_t)202, (int16_t)-171, (int16_t)622, (int16_t)1577, (int16_t)182, (int16_t)962, (int16_t)-1202, (int16_t)-1474, (int16_t)1468, (int16_t)573, (int16_t)-1325, (int16_t)264, (int16_t)383, (int16_t)-829, (int16_t)1458, (int16_t)-1602, (int16_t)-130, (int16_t)-681, (int16_t)1017, (int16_t)732, (int16_t)608, (int16_t)-1542, (int16_t)411, (int16_t)-205, (int16_t)-1571, (int16_t)1223, (int16_t)652, (int16_t)-552, (int16_t)1015, (int16_t)-1293, (int16_t)1491, (int16_t)-282, (int16_t)-1544, (int16_t)516, (int16_t)-8, (int16_t)-320, (int16_t)-666, (int16_t)-1618, (int16_t)-1162, (int16_t)126, (int16_t)1469, (int16_t)-853, (int16_t)-90, (int16_t)-271, (int16_t)830, (int16_t)107, (int16_t)-1421, (int16_t)-247, (int16_t)-951, (int16_t)-398, (int16_t)961, (int16_t)-1508, (int16_t)-725, (int16_t)448, (int16_t)-1065, (int16_t)677, (int16_t)-1275, (int16_t)-1103, (int16_t)430, (int16_t)555, (int16_t)843, (int16_t)-1251, (int16_t)871, (int16_t)1550, (int16_t)105, (int16_t)422, (int16_t)587, (int16_t)177, (int16_t)-235, (int16_t)-291, (int16_t)-460, (int16_t)1574, (int16_t)1653, (int16_t)-246, (int16_t)778, (int16_t)1159, (int16_t)-147, (int16_t)-777, (int16_t)1483, (int16_t)-602, (int16_t)1119, (int16_t)-1590, (int16_t)644, (int16_t)-872, (int16_t)349, (int16_t)418, (int16_t)329, (int16_t)-156, (int16_t)-75, (int16_t)817, (int16_t)1097, (int16_t)603, (int16_t)610, (int16_t)1322, (int16_t)-1285, (int16_t)-1465, (int16_t)384, (int16_t)-1215, (int16_t)-136, (int16_t)1218, (int16_t)-1335, (int16_t)-874, (int16_t)220, (int16_t)-1187, (int16_t)-1659, (int16_t)-1185, (int16_t)-1530, (int16_t)-1278, (int16_t)794, (int16_t)-1510, (int16_t)-854, (int16_t)-870, (int16_t)478, (int16_t)-108, (int16_t)-308, (int16_t)996, (int16_t)991, (int16_t)958, (int16_t)-1460, (int16_t)1522, (int16_t)1628 } }))

static KRML_MUSTINLINE int16_t libcrux_ml_kem_polynomial_zeta(size_t i)
{
  return LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R.data[i];
}

#define LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT ((size_t)16U)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR ((size_t)16U)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_MONTGOMERY_R_SQUARED_MOD_FIELD_MODULUS ((int16_t)1353)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS ((int16_t)3329)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R (62209U)

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_vector_type_from_i16_array(Eurydice_borrow_slice_i16 array)
{
  Eurydice_arr_e2 arr;
  memcpy(arr.data,
    Eurydice_slice_subslice_shared_76(array,
      ((core_ops_range_Range_08){ (size_t)0U, (size_t)16U })).ptr,
    (size_t)16U * sizeof (int16_t));
  return unwrap_26_0e((Result_f4){ .tag = Ok, .val = { .case_Ok = arr } });
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_from_i16_array_b8(Eurydice_borrow_slice_i16 array)
{
  return
    libcrux_ml_kem_vector_portable_vector_type_from_i16_array(libcrux_secrets_int_classify_public_classify_ref_9b_39(array));
}

typedef struct int16_t_x8_s
{
  int16_t fst;
  int16_t snd;
  int16_t thd;
  int16_t f3;
  int16_t f4;
  int16_t f5;
  int16_t f6;
  int16_t f7;
}
int16_t_x8;

static KRML_MUSTINLINE Eurydice_arr_e2 libcrux_ml_kem_vector_portable_vector_type_zero(void)
{
  return libcrux_secrets_int_public_integers_classify_27_3a(((Eurydice_arr_e2){ { 0U } }));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2 libcrux_ml_kem_vector_portable_ZERO_b8(void)
{
  return libcrux_ml_kem_vector_portable_vector_type_zero();
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_add(Eurydice_arr_e2 lhs, const Eurydice_arr_e2 *rhs)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    size_t uu____0 = i0;
    lhs.data[uu____0] = lhs.data[uu____0] + rhs->data[i0];
  }
  return lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_add_b8(Eurydice_arr_e2 lhs, const Eurydice_arr_e2 *rhs)
{
  return libcrux_ml_kem_vector_portable_arithmetic_add(lhs, rhs);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_sub(Eurydice_arr_e2 lhs, const Eurydice_arr_e2 *rhs)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    size_t uu____0 = i0;
    lhs.data[uu____0] = lhs.data[uu____0] - rhs->data[i0];
  }
  return lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_sub_b8(Eurydice_arr_e2 lhs, const Eurydice_arr_e2 *rhs)
{
  return libcrux_ml_kem_vector_portable_arithmetic_sub(lhs, rhs);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_multiply_by_constant(Eurydice_arr_e2 vec, int16_t c)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    size_t uu____0 = i0;
    vec.data[uu____0] = vec.data[uu____0] * c;
  }
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_multiply_by_constant_b8(Eurydice_arr_e2 vec, int16_t c)
{
  return libcrux_ml_kem_vector_portable_arithmetic_multiply_by_constant(vec, c);
}

/**
 Note: This function is not secret independent
 Only use with public values.
*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_cond_subtract_3329(Eurydice_arr_e2 vec)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    if (libcrux_secrets_int_public_integers_declassify_d8_39(vec.data[i0]) >= (int16_t)3329)
    {
      size_t uu____0 = i0;
      vec.data[uu____0] = vec.data[uu____0] - (int16_t)3329;
    }
  }
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_cond_subtract_3329_b8(Eurydice_arr_e2 v)
{
  return libcrux_ml_kem_vector_portable_arithmetic_cond_subtract_3329(v);
}

#define LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER ((int32_t)20159)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT ((int32_t)26)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_R ((int32_t)1 << (uint32_t)LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT)

/**
 Signed Barrett Reduction

 Given an input `value`, `barrett_reduce` outputs a representative `result`
 such that:

 - result ≡ value (mod FIELD_MODULUS)
 - the absolute value of `result` is bound as follows:

 `|result| ≤ FIELD_MODULUS / 2 · (|value|/BARRETT_R + 1)

 Note: The input bound is 28296 to prevent overflow in the multiplication of quotient by FIELD_MODULUS

*/
static inline int16_t
libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(int16_t value)
{
  int32_t
  t =
    libcrux_secrets_int_as_i32_f5(value) *
      LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER
    + (LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_R >> 1U);
  int16_t
  quotient =
    libcrux_secrets_int_as_i16_36(t >> (uint32_t)LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT);
  return value - quotient * LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS;
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce(Eurydice_arr_e2 vec)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    int16_t vi = libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(vec.data[i0]);
    vec.data[i0] = vi;
  }
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_barrett_reduce_b8(Eurydice_arr_e2 vector)
{
  return libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce(vector);
}

#define LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT (16U)

/**
 Signed Montgomery Reduction

 Given an input `value`, `montgomery_reduce` outputs a representative `o`
 such that:

 - o ≡ value · MONTGOMERY_R^(-1) (mod FIELD_MODULUS)
 - the absolute value of `o` is bound as follows:

 `|result| ≤ ceil(|value| / MONTGOMERY_R) + 1665

 In particular, if `|value| ≤ FIELD_MODULUS-1 * FIELD_MODULUS-1`, then `|o| <= FIELD_MODULUS-1`.
 And, if `|value| ≤ pow2 16 * FIELD_MODULUS-1`, then `|o| <= FIELD_MODULUS + 1664

*/
static inline int16_t
libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(int32_t value)
{
  int32_t
  k =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(value)) *
      libcrux_secrets_int_as_i32_b8(libcrux_secrets_int_public_integers_classify_27_df(LIBCRUX_ML_KEM_VECTOR_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R));
  int32_t
  k_times_modulus =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(k)) *
      libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_public_integers_classify_27_39(LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS));
  int16_t
  c =
    libcrux_secrets_int_as_i16_36(k_times_modulus >>
        (uint32_t)LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  int16_t
  value_high =
    libcrux_secrets_int_as_i16_36(value >>
        (uint32_t)LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  return value_high - c;
}

/**
 If `fe` is some field element 'x' of the Kyber field and `fer` is congruent to
 `y · MONTGOMERY_R`, this procedure outputs a value that is congruent to
 `x · y`, as follows:

    `fe · fer ≡ x · y · MONTGOMERY_R (mod FIELD_MODULUS)`

 `montgomery_reduce` takes the value `x · y · MONTGOMERY_R` and outputs a representative
 `x · y · MONTGOMERY_R * MONTGOMERY_R^{-1} ≡ x · y (mod FIELD_MODULUS)`.
*/
static KRML_MUSTINLINE int16_t
libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(
  int16_t fe,
  int16_t fer
)
{
  int32_t product = libcrux_secrets_int_as_i32_f5(fe) * libcrux_secrets_int_as_i32_f5(fer);
  return libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(product);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_e2 vec,
  int16_t c
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    vec.data[i0] =
      libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(vec.data[i0],
        c);
  }
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(
  Eurydice_arr_e2 vector,
  int16_t constant
)
{
  return
    libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_by_constant(vector,
      libcrux_secrets_int_public_integers_classify_27_39(constant));
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(
  Eurydice_arr_e2 vec,
  int16_t c
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    size_t uu____0 = i0;
    vec.data[uu____0] = vec.data[uu____0] & c;
  }
  return vec;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.arithmetic.shift_right
with const generics
- SHIFT_BY= 15
*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_shift_right_ef(Eurydice_arr_e2 vec)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    vec.data[i0] = vec.data[i0] >> (uint32_t)(int32_t)15;
  }
  return vec;
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_arithmetic_to_unsigned_representative(Eurydice_arr_e2 a)
{
  Eurydice_arr_e2 t = libcrux_ml_kem_vector_portable_arithmetic_shift_right_ef(a);
  Eurydice_arr_e2
  fm =
    libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(t,
      LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS);
  return libcrux_ml_kem_vector_portable_arithmetic_add(a, &fm);
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_to_unsigned_representative_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_arithmetic_to_unsigned_representative(a);
}

/**
 The `compress_*` functions implement the `Compress` function specified in the NIST FIPS
 203 standard (Page 18, Expression 4.5), which is defined as:

 ```plaintext
 Compress_d: ℤq -> ℤ(_){2ᵈ}
 Compress_d(x) = ⌈(2ᵈ/q)·x⌋
 ```

 Since `⌈x⌋ = ⌊x + 1/2⌋` we have:

 ```plaintext
 Compress_d(x) = ⌊(2ᵈ/q)·x + 1/2⌋
               = ⌊(2^{d+1}·x + q) / 2q⌋
 ```

 For further information about the function implementations, consult the
 `implementation_notes.pdf` document in this directory.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
static inline uint8_t
libcrux_ml_kem_vector_portable_compress_compress_message_coefficient(uint16_t fe)
{
  int16_t
  shifted =
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)1664) -
      libcrux_secrets_int_as_i16_ca(fe);
  int16_t mask = shifted >> 15U;
  int16_t shifted_to_positive = mask ^ shifted;
  int16_t shifted_positive_in_range = shifted_to_positive - (int16_t)832;
  int16_t r0 = shifted_positive_in_range >> 15U;
  int16_t r1 = r0 & (int16_t)1;
  return libcrux_secrets_int_as_u8_f5(r1);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_compress_compress_1(Eurydice_arr_e2 a)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    a.data[i0] =
      libcrux_secrets_int_as_i16_59(libcrux_ml_kem_vector_portable_compress_compress_message_coefficient(libcrux_secrets_int_as_u16_f5(a.data[i0])));
  }
  return a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2 libcrux_ml_kem_vector_portable_compress_1_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_compress_compress_1(a);
}

static KRML_MUSTINLINE uint32_t
libcrux_ml_kem_vector_portable_arithmetic_get_n_least_significant_bits(
  uint8_t n,
  uint32_t value
)
{
  return value & ((1U << (uint32_t)n) - 1U);
}

static inline int16_t
libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient(
  uint8_t coefficient_bits,
  uint16_t fe
)
{
  uint64_t compressed = libcrux_secrets_int_as_u64_ca(fe) << (uint32_t)coefficient_bits;
  compressed = compressed + 1664ULL;
  compressed = compressed * 10321340ULL;
  compressed = compressed >> 35U;
  return
    libcrux_secrets_int_as_i16_b8(libcrux_ml_kem_vector_portable_arithmetic_get_n_least_significant_bits(coefficient_bits,
        libcrux_secrets_int_as_u32_a3(compressed)));
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_compress_decompress_1(Eurydice_arr_e2 a)
{
  Eurydice_arr_e2 z = libcrux_ml_kem_vector_portable_vector_type_zero();
  Eurydice_arr_e2 s = libcrux_ml_kem_vector_portable_arithmetic_sub(z, &a);
  Eurydice_arr_e2
  res = libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(s, (int16_t)1665);
  return res;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2 libcrux_ml_kem_vector_portable_decompress_1_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_compress_decompress_1(a);
}

static KRML_MUSTINLINE void
libcrux_ml_kem_vector_portable_ntt_ntt_step(
  Eurydice_arr_e2 *vec,
  int16_t zeta,
  size_t i,
  size_t j
)
{
  int16_t
  t =
    libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(vec->data[j],
      libcrux_secrets_int_public_integers_classify_27_39(zeta));
  int16_t a_minus_t = vec->data[i] - t;
  int16_t a_plus_t = vec->data[i] + t;
  vec->data[j] = a_minus_t;
  vec->data[i] = a_plus_t;
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_ntt_layer_1_step(
  Eurydice_arr_e2 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (size_t)0U, (size_t)2U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (size_t)1U, (size_t)3U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (size_t)4U, (size_t)6U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (size_t)5U, (size_t)7U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta2, (size_t)8U, (size_t)10U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta2, (size_t)9U, (size_t)11U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta3, (size_t)12U, (size_t)14U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta3, (size_t)13U, (size_t)15U);
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_layer_1_step_b8(
  Eurydice_arr_e2 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  return libcrux_ml_kem_vector_portable_ntt_ntt_layer_1_step(a, zeta0, zeta1, zeta2, zeta3);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_ntt_layer_2_step(
  Eurydice_arr_e2 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (size_t)0U, (size_t)4U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (size_t)1U, (size_t)5U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (size_t)2U, (size_t)6U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (size_t)3U, (size_t)7U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (size_t)8U, (size_t)12U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (size_t)9U, (size_t)13U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (size_t)10U, (size_t)14U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (size_t)11U, (size_t)15U);
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_layer_2_step_b8(
  Eurydice_arr_e2 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  return libcrux_ml_kem_vector_portable_ntt_ntt_layer_2_step(a, zeta0, zeta1);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_ntt_layer_3_step(Eurydice_arr_e2 vec, int16_t zeta)
{
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)0U, (size_t)8U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)1U, (size_t)9U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)2U, (size_t)10U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)3U, (size_t)11U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)4U, (size_t)12U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)5U, (size_t)13U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)6U, (size_t)14U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (size_t)7U, (size_t)15U);
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_layer_3_step_b8(Eurydice_arr_e2 a, int16_t zeta)
{
  return libcrux_ml_kem_vector_portable_ntt_ntt_layer_3_step(a, zeta);
}

static KRML_MUSTINLINE void
libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(
  Eurydice_arr_e2 *vec,
  int16_t zeta,
  size_t i,
  size_t j
)
{
  int16_t a_minus_b = vec->data[j] - vec->data[i];
  int16_t a_plus_b = vec->data[j] + vec->data[i];
  int16_t o0 = libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(a_plus_b);
  int16_t
  o1 =
    libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      libcrux_secrets_int_public_integers_classify_27_39(zeta));
  vec->data[i] = o0;
  vec->data[j] = o1;
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_1_step(
  Eurydice_arr_e2 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (size_t)0U, (size_t)2U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (size_t)1U, (size_t)3U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (size_t)4U, (size_t)6U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (size_t)5U, (size_t)7U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta2, (size_t)8U, (size_t)10U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta2, (size_t)9U, (size_t)11U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta3, (size_t)12U, (size_t)14U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta3, (size_t)13U, (size_t)15U);
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_inv_ntt_layer_1_step_b8(
  Eurydice_arr_e2 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  return libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_1_step(a, zeta0, zeta1, zeta2, zeta3);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_2_step(
  Eurydice_arr_e2 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (size_t)0U, (size_t)4U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (size_t)1U, (size_t)5U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (size_t)2U, (size_t)6U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (size_t)3U, (size_t)7U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (size_t)8U, (size_t)12U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (size_t)9U, (size_t)13U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (size_t)10U, (size_t)14U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (size_t)11U, (size_t)15U);
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_inv_ntt_layer_2_step_b8(
  Eurydice_arr_e2 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  return libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_2_step(a, zeta0, zeta1);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_3_step(Eurydice_arr_e2 vec, int16_t zeta)
{
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)0U, (size_t)8U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)1U, (size_t)9U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)2U, (size_t)10U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)3U, (size_t)11U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)4U, (size_t)12U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)5U, (size_t)13U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)6U, (size_t)14U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (size_t)7U, (size_t)15U);
  return vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_inv_ntt_layer_3_step_b8(Eurydice_arr_e2 a, int16_t zeta)
{
  return libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_3_step(a, zeta);
}

/**
 Compute the product of two Kyber binomials with respect to the
 modulus `X² - zeta`.

 This function almost implements <strong>Algorithm 11</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input:  a₀, a₁, b₀, b₁ ∈ ℤq.
 Input: γ ∈ ℤq.
 Output: c₀, c₁ ∈ ℤq.

 c₀ ← a₀·b₀ + a₁·b₁·γ
 c₁ ← a₀·b₁ + a₁·b₀
 return c₀, c₁
 ```
 We say "almost" because the coefficients output by this function are in
 the Montgomery domain (unlike in the specification).

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(
  const Eurydice_arr_e2 *a,
  const Eurydice_arr_e2 *b,
  int16_t zeta,
  size_t i,
  Eurydice_arr_e2 *out
)
{
  int16_t ai = a->data[(size_t)2U * i];
  int16_t bi = b->data[(size_t)2U * i];
  int16_t aj = a->data[(size_t)2U * i + (size_t)1U];
  int16_t bj = b->data[(size_t)2U * i + (size_t)1U];
  int32_t ai_bi = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t aj_bj_ = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bj);
  int16_t aj_bj = libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(aj_bj_);
  int32_t
  aj_bj_zeta = libcrux_secrets_int_as_i32_f5(aj_bj) * libcrux_secrets_int_as_i32_f5(zeta);
  int32_t ai_bi_aj_bj = ai_bi + aj_bj_zeta;
  int16_t o0 = libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(ai_bi_aj_bj);
  int32_t ai_bj = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bj);
  int32_t aj_bi = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t ai_bj_aj_bi = ai_bj + aj_bi;
  int16_t o1 = libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(ai_bj_aj_bi);
  out->data[(size_t)2U * i] = o0;
  out->data[(size_t)2U * i + (size_t)1U] = o1;
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_ntt_multiply(
  const Eurydice_arr_e2 *lhs,
  const Eurydice_arr_e2 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  int16_t nzeta0 = -zeta0;
  int16_t nzeta1 = -zeta1;
  int16_t nzeta2 = -zeta2;
  int16_t nzeta3 = -zeta3;
  Eurydice_arr_e2 out = libcrux_ml_kem_vector_portable_vector_type_zero();
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta0),
    (size_t)0U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta0),
    (size_t)1U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta1),
    (size_t)2U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta1),
    (size_t)3U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta2),
    (size_t)4U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta2),
    (size_t)5U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta3),
    (size_t)6U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta3),
    (size_t)7U,
    &out);
  return out;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_ntt_multiply_b8(
  const Eurydice_arr_e2 *lhs,
  const Eurydice_arr_e2 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  return libcrux_ml_kem_vector_portable_ntt_ntt_multiply(lhs, rhs, zeta0, zeta1, zeta2, zeta3);
}

static KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_ml_kem_vector_portable_serialize_serialize_1(Eurydice_arr_e2 v)
{
  uint8_t
  result0 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.data[0U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[1U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[2U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[3U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[4U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[5U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[6U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[7U]) << 7U;
  uint8_t
  result1 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.data[8U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[9U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[10U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[11U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[12U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[13U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[14U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.data[15U]) << 7U;
  return ((Eurydice_array_u8x2){ { result0, result1 } });
}

static inline Eurydice_array_u8x2 libcrux_ml_kem_vector_portable_serialize_1(Eurydice_arr_e2 a)
{
  return
    libcrux_secrets_int_public_integers_declassify_d8_ee0(libcrux_ml_kem_vector_portable_serialize_serialize_1(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_array_u8x2
libcrux_ml_kem_vector_portable_serialize_1_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_serialize_1(a);
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_serialize_deserialize_1(Eurydice_borrow_slice_u8 v)
{
  int16_t result0 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] & 1U);
  int16_t result1 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 1U & 1U);
  int16_t result2 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 2U & 1U);
  int16_t result3 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 3U & 1U);
  int16_t result4 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 4U & 1U);
  int16_t result5 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 5U & 1U);
  int16_t result6 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 6U & 1U);
  int16_t result7 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 7U & 1U);
  int16_t result8 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] & 1U);
  int16_t result9 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 1U & 1U);
  int16_t result10 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 2U & 1U);
  int16_t result11 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 3U & 1U);
  int16_t result12 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 4U & 1U);
  int16_t result13 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 5U & 1U);
  int16_t result14 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 6U & 1U);
  int16_t result15 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 7U & 1U);
  return
    (
      (Eurydice_arr_e2){
        {
          result0, result1, result2, result3, result4, result5, result6, result7, result8, result9,
          result10, result11, result12, result13, result14, result15
        }
      }
    );
}

static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_1(Eurydice_borrow_slice_u8 a)
{
  return
    libcrux_ml_kem_vector_portable_serialize_deserialize_1(libcrux_secrets_int_classify_public_classify_ref_9b_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_1_b8(Eurydice_borrow_slice_u8 a)
{
  return libcrux_ml_kem_vector_portable_deserialize_1(a);
}

typedef struct uint8_t_x4_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
}
uint8_t_x4;

static KRML_MUSTINLINE uint8_t_x4
libcrux_ml_kem_vector_portable_serialize_serialize_4_int(Eurydice_borrow_slice_i16 v)
{
  uint8_t
  result0 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[0U]);
  uint8_t
  result1 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[3U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U]);
  uint8_t
  result2 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[5U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[4U]);
  uint8_t
  result3 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[7U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[6U]);
  return ((uint8_t_x4){ result0, result1, result2, result3 });
}

static KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_ml_kem_vector_portable_serialize_serialize_4(Eurydice_arr_e2 v)
{
  uint8_t_x4
  result0_3 =
    libcrux_ml_kem_vector_portable_serialize_serialize_4_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)8U })));
  uint8_t_x4
  result4_7 =
    libcrux_ml_kem_vector_portable_serialize_serialize_4_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)8U, (size_t)16U })));
  return
    (
      (Eurydice_array_u8x8){
        {
          result0_3.fst, result0_3.snd, result0_3.thd, result0_3.f3, result4_7.fst, result4_7.snd,
          result4_7.thd, result4_7.f3
        }
      }
    );
}

static inline Eurydice_array_u8x8 libcrux_ml_kem_vector_portable_serialize_4(Eurydice_arr_e2 a)
{
  return
    libcrux_secrets_int_public_integers_declassify_d8_36(libcrux_ml_kem_vector_portable_serialize_serialize_4(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_array_u8x8
libcrux_ml_kem_vector_portable_serialize_4_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_serialize_4(a);
}

static KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(Eurydice_borrow_slice_u8 bytes)
{
  int16_t v0 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[0U] & 15U);
  int16_t v1 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[0U] >> 4U & 15U);
  int16_t v2 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[1U] & 15U);
  int16_t v3 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[1U] >> 4U & 15U);
  int16_t v4 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[2U] & 15U);
  int16_t v5 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[2U] >> 4U & 15U);
  int16_t v6 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[3U] & 15U);
  int16_t v7 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[3U] >> 4U & 15U);
  return ((int16_t_x8){ v0, v1, v2, v3, v4, v5, v6, v7 });
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_serialize_deserialize_4(Eurydice_borrow_slice_u8 bytes)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)4U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)4U, (size_t)8U })));
  return
    (
      (Eurydice_arr_e2){
        {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_4(Eurydice_borrow_slice_u8 a)
{
  return
    libcrux_ml_kem_vector_portable_serialize_deserialize_4(libcrux_secrets_int_classify_public_classify_ref_9b_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_4_b8(Eurydice_borrow_slice_u8 a)
{
  return libcrux_ml_kem_vector_portable_deserialize_4(a);
}

typedef struct uint8_t_x5_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
  uint8_t f4;
}
uint8_t_x5;

static KRML_MUSTINLINE uint8_t_x5
libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_borrow_slice_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & (int16_t)255);
  uint8_t
  r1 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U] & (int16_t)63) << 2U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U & (int16_t)3);
  uint8_t
  r2 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U] & (int16_t)15) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 6U & (int16_t)15);
  uint8_t
  r3 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[3U] & (int16_t)3) << 6U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U] >> 4U & (int16_t)63);
  uint8_t r4 = libcrux_secrets_int_as_u8_f5(v.ptr[3U] >> 2U & (int16_t)255);
  return ((uint8_t_x5){ r0, r1, r2, r3, r4 });
}

static KRML_MUSTINLINE Eurydice_arr_dc
libcrux_ml_kem_vector_portable_serialize_serialize_10(Eurydice_arr_e2 v)
{
  uint8_t_x5
  r0_4 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)4U })));
  uint8_t_x5
  r5_9 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)4U, (size_t)8U })));
  uint8_t_x5
  r10_14 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)8U, (size_t)12U })));
  uint8_t_x5
  r15_19 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)12U, (size_t)16U })));
  return
    (
      (Eurydice_arr_dc){
        {
          r0_4.fst, r0_4.snd, r0_4.thd, r0_4.f3, r0_4.f4, r5_9.fst, r5_9.snd, r5_9.thd, r5_9.f3,
          r5_9.f4, r10_14.fst, r10_14.snd, r10_14.thd, r10_14.f3, r10_14.f4, r15_19.fst, r15_19.snd,
          r15_19.thd, r15_19.f3, r15_19.f4
        }
      }
    );
}

static inline Eurydice_arr_dc libcrux_ml_kem_vector_portable_serialize_10(Eurydice_arr_e2 a)
{
  return
    libcrux_secrets_int_public_integers_declassify_d8_89(libcrux_ml_kem_vector_portable_serialize_serialize_10(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_dc libcrux_ml_kem_vector_portable_serialize_10_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_serialize_10(a);
}

static KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(Eurydice_borrow_slice_u8 bytes)
{
  int16_t
  r0 =
    libcrux_secrets_int_as_i16_f5((libcrux_secrets_int_as_i16_59(bytes.ptr[1U]) & (int16_t)3) << 8U
      | (libcrux_secrets_int_as_i16_59(bytes.ptr[0U]) & (int16_t)255));
  int16_t
  r1 =
    libcrux_secrets_int_as_i16_f5((libcrux_secrets_int_as_i16_59(bytes.ptr[2U]) & (int16_t)15) <<
        6U
      | libcrux_secrets_int_as_i16_59(bytes.ptr[1U]) >> 2U);
  int16_t
  r2 =
    libcrux_secrets_int_as_i16_f5((libcrux_secrets_int_as_i16_59(bytes.ptr[3U]) & (int16_t)63) <<
        4U
      | libcrux_secrets_int_as_i16_59(bytes.ptr[2U]) >> 4U);
  int16_t
  r3 =
    libcrux_secrets_int_as_i16_f5(libcrux_secrets_int_as_i16_59(bytes.ptr[4U]) << 2U |
        libcrux_secrets_int_as_i16_59(bytes.ptr[3U]) >> 6U);
  int16_t
  r4 =
    libcrux_secrets_int_as_i16_f5((libcrux_secrets_int_as_i16_59(bytes.ptr[6U]) & (int16_t)3) << 8U
      | (libcrux_secrets_int_as_i16_59(bytes.ptr[5U]) & (int16_t)255));
  int16_t
  r5 =
    libcrux_secrets_int_as_i16_f5((libcrux_secrets_int_as_i16_59(bytes.ptr[7U]) & (int16_t)15) <<
        6U
      | libcrux_secrets_int_as_i16_59(bytes.ptr[6U]) >> 2U);
  int16_t
  r6 =
    libcrux_secrets_int_as_i16_f5((libcrux_secrets_int_as_i16_59(bytes.ptr[8U]) & (int16_t)63) <<
        4U
      | libcrux_secrets_int_as_i16_59(bytes.ptr[7U]) >> 4U);
  int16_t
  r7 =
    libcrux_secrets_int_as_i16_f5(libcrux_secrets_int_as_i16_59(bytes.ptr[9U]) << 2U |
        libcrux_secrets_int_as_i16_59(bytes.ptr[8U]) >> 6U);
  return ((int16_t_x8){ r0, r1, r2, r3, r4, r5, r6, r7 });
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_serialize_deserialize_10(Eurydice_borrow_slice_u8 bytes)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)10U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)10U, (size_t)20U })));
  return
    (
      (Eurydice_arr_e2){
        {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_10(Eurydice_borrow_slice_u8 a)
{
  return
    libcrux_ml_kem_vector_portable_serialize_deserialize_10(libcrux_secrets_int_classify_public_classify_ref_9b_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_10_b8(Eurydice_borrow_slice_u8 a)
{
  return libcrux_ml_kem_vector_portable_deserialize_10(a);
}

typedef struct uint8_t_x3_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
}
uint8_t_x3;

static KRML_MUSTINLINE uint8_t_x3
libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_borrow_slice_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & (int16_t)255);
  uint8_t r1 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U | (v.ptr[1U] & (int16_t)15) << 4U);
  uint8_t r2 = libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 4U & (int16_t)255);
  return ((uint8_t_x3){ r0, r1, r2 });
}

static KRML_MUSTINLINE Eurydice_arr_6d
libcrux_ml_kem_vector_portable_serialize_serialize_12(Eurydice_arr_e2 v)
{
  uint8_t_x3
  r0_2 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)2U })));
  uint8_t_x3
  r3_5 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)2U, (size_t)4U })));
  uint8_t_x3
  r6_8 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)4U, (size_t)6U })));
  uint8_t_x3
  r9_11 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)6U, (size_t)8U })));
  uint8_t_x3
  r12_14 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)8U, (size_t)10U })));
  uint8_t_x3
  r15_17 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)10U, (size_t)12U })));
  uint8_t_x3
  r18_20 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)12U, (size_t)14U })));
  uint8_t_x3
  r21_23 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_85(&v,
        ((core_ops_range_Range_08){ (size_t)14U, (size_t)16U })));
  return
    (
      (Eurydice_arr_6d){
        {
          r0_2.fst, r0_2.snd, r0_2.thd, r3_5.fst, r3_5.snd, r3_5.thd, r6_8.fst, r6_8.snd, r6_8.thd,
          r9_11.fst, r9_11.snd, r9_11.thd, r12_14.fst, r12_14.snd, r12_14.thd, r15_17.fst,
          r15_17.snd, r15_17.thd, r18_20.fst, r18_20.snd, r18_20.thd, r21_23.fst, r21_23.snd,
          r21_23.thd
        }
      }
    );
}

static inline Eurydice_arr_6d libcrux_ml_kem_vector_portable_serialize_12(Eurydice_arr_e2 a)
{
  return
    libcrux_secrets_int_public_integers_declassify_d8_bd(libcrux_ml_kem_vector_portable_serialize_serialize_12(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_6d libcrux_ml_kem_vector_portable_serialize_12_b8(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_serialize_12(a);
}

typedef struct int16_t_x2_s
{
  int16_t fst;
  int16_t snd;
}
int16_t_x2;

static KRML_MUSTINLINE int16_t_x2
libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_borrow_slice_u8 bytes)
{
  int16_t byte0 = libcrux_secrets_int_as_i16_59(bytes.ptr[0U]);
  int16_t byte1 = libcrux_secrets_int_as_i16_59(bytes.ptr[1U]);
  int16_t byte2 = libcrux_secrets_int_as_i16_59(bytes.ptr[2U]);
  int16_t r0 = (byte1 & (int16_t)15) << 8U | (byte0 & (int16_t)255);
  int16_t r1 = byte2 << 4U | (byte1 >> 4U & (int16_t)15);
  return ((int16_t_x2){ r0, r1 });
}

static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_serialize_deserialize_12(Eurydice_borrow_slice_u8 bytes)
{
  int16_t_x2
  v0_1 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)3U })));
  int16_t_x2
  v2_3 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)3U, (size_t)6U })));
  int16_t_x2
  v4_5 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)6U, (size_t)9U })));
  int16_t_x2
  v6_7 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)9U, (size_t)12U })));
  int16_t_x2
  v8_9 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)12U, (size_t)15U })));
  int16_t_x2
  v10_11 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)15U, (size_t)18U })));
  int16_t_x2
  v12_13 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)18U, (size_t)21U })));
  int16_t_x2
  v14_15 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_7e(bytes,
        ((core_ops_range_Range_08){ (size_t)21U, (size_t)24U })));
  return
    (
      (Eurydice_arr_e2){
        {
          v0_1.fst, v0_1.snd, v2_3.fst, v2_3.snd, v4_5.fst, v4_5.snd, v6_7.fst, v6_7.snd, v8_9.fst,
          v8_9.snd, v10_11.fst, v10_11.snd, v12_13.fst, v12_13.snd, v14_15.fst, v14_15.snd
        }
      }
    );
}

static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_12(Eurydice_borrow_slice_u8 a)
{
  return
    libcrux_ml_kem_vector_portable_serialize_deserialize_12(libcrux_secrets_int_classify_public_classify_ref_9b_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_deserialize_12_b8(Eurydice_borrow_slice_u8 a)
{
  return libcrux_ml_kem_vector_portable_deserialize_12(a);
}

static KRML_MUSTINLINE size_t
libcrux_ml_kem_vector_portable_sampling_rej_sample(
  Eurydice_borrow_slice_u8 a,
  Eurydice_mut_borrow_slice_i16 result
)
{
  size_t sampled = (size_t)0U;
  for (size_t i = (size_t)0U; i < a.meta / (size_t)3U; i++)
  {
    size_t i0 = i;
    int16_t b1 = (int16_t)a.ptr[i0 * (size_t)3U + (size_t)0U];
    int16_t b2 = (int16_t)a.ptr[i0 * (size_t)3U + (size_t)1U];
    int16_t b3 = (int16_t)a.ptr[i0 * (size_t)3U + (size_t)2U];
    int16_t d1 = (b2 & (int16_t)15) << 8U | b1;
    int16_t d2 = b3 << 4U | b2 >> 4U;
    if (d1 < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS)
    {
      if (sampled < (size_t)16U)
      {
        result.ptr[sampled] = d1;
        sampled++;
      }
    }
    if (d2 < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS)
    {
      if (sampled < (size_t)16U)
      {
        result.ptr[sampled] = d2;
        sampled++;
      }
    }
  }
  return sampled;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
static inline size_t
libcrux_ml_kem_vector_portable_rej_sample_b8(
  Eurydice_borrow_slice_u8 a,
  Eurydice_mut_borrow_slice_i16 out
)
{
  return libcrux_ml_kem_vector_portable_sampling_rej_sample(a, out);
}

#define LIBCRUX_ML_KEM_MLKEM768_VECTOR_U_COMPRESSION_FACTOR ((size_t)10U)

#define LIBCRUX_ML_KEM_MLKEM768_C1_BLOCK_SIZE (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_VECTOR_U_COMPRESSION_FACTOR / (size_t)8U)

#define LIBCRUX_ML_KEM_MLKEM768_RANK ((size_t)3U)

#define LIBCRUX_ML_KEM_MLKEM768_C1_SIZE (LIBCRUX_ML_KEM_MLKEM768_C1_BLOCK_SIZE * LIBCRUX_ML_KEM_MLKEM768_RANK)

#define LIBCRUX_ML_KEM_MLKEM768_VECTOR_V_COMPRESSION_FACTOR ((size_t)4U)

#define LIBCRUX_ML_KEM_MLKEM768_C2_SIZE (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_VECTOR_V_COMPRESSION_FACTOR / (size_t)8U)

#define LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE (LIBCRUX_ML_KEM_MLKEM768_C1_SIZE + LIBCRUX_ML_KEM_MLKEM768_C2_SIZE)

#define LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_SIZE (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_COEFFICIENT / (size_t)8U)

#define LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_KEY_SIZE (LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_SIZE + (size_t)32U)

#define LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_KEY_SIZE (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_COEFFICIENT / (size_t)8U)

#define LIBCRUX_ML_KEM_MLKEM768_ETA1 ((size_t)2U)

#define LIBCRUX_ML_KEM_MLKEM768_ETA1_RANDOMNESS_SIZE (LIBCRUX_ML_KEM_MLKEM768_ETA1 * (size_t)64U)

#define LIBCRUX_ML_KEM_MLKEM768_ETA2 ((size_t)2U)

#define LIBCRUX_ML_KEM_MLKEM768_ETA2_RANDOMNESS_SIZE (LIBCRUX_ML_KEM_MLKEM768_ETA2 * (size_t)64U)

#define LIBCRUX_ML_KEM_MLKEM768_IMPLICIT_REJECTION_HASH_INPUT_SIZE (LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE)

typedef Eurydice_arr_ea libcrux_ml_kem_mlkem768_MlKem768PrivateKey;

typedef Eurydice_arr_74 libcrux_ml_kem_mlkem768_MlKem768PublicKey;

#define LIBCRUX_ML_KEM_MLKEM768_RANKED_BYTES_PER_RING_ELEMENT (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT / (size_t)8U)

#define LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE (LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_KEY_SIZE + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_KEY_SIZE + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE + LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE)

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $16size_t
*/
typedef struct Eurydice_arr_b9_s { Eurydice_arr_e2 data[16U]; } Eurydice_arr_b9;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_polynomial_PolynomialRingElement_1d
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_1d_s { Eurydice_arr_b9 data[3U]; } Eurydice_arr_1d;

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static inline Eurydice_arr_b9 libcrux_ml_kem_polynomial_ZERO_d6_ea(void)
{
  Eurydice_arr_b9 lit;
  Eurydice_arr_e2 repeat_expression[16U];
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    repeat_expression[i] = libcrux_ml_kem_vector_portable_ZERO_b8();
  }
  memcpy(lit.data, repeat_expression, (size_t)16U * sizeof (Eurydice_arr_e2));
  return lit;
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cpa::decrypt::closure<Vector, K, CIPHERTEXT_SIZE, VECTOR_U_ENCODED_SIZE, U_COMPRESSION_FACTOR, V_COMPRESSION_FACTOR>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt.call_mut_0b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_42(void **_, size_t tupled_args)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_to_uncompressed_ring_element_ea(
  Eurydice_borrow_slice_u8 serialized
)
{
  Eurydice_arr_b9 re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)24U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)24U, i0 * (size_t)24U + (size_t)24U }));
    Eurydice_arr_e2 uu____0 = libcrux_ml_kem_vector_portable_deserialize_12_b8(bytes);
    re.data[i0] = uu____0;
  }
  return re;
}

/**
 Call [`deserialize_to_uncompressed_ring_element`] for each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_vector
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_deserialize_vector_1b(
  Eurydice_borrow_slice_u8 secret_key,
  Eurydice_arr_1d *secret_as_ntt
)
{
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9
    uu____0 =
      libcrux_ml_kem_serialize_deserialize_to_uncompressed_ring_element_ea(Eurydice_slice_subslice_shared_7e(secret_key,
          (
            (core_ops_range_Range_08){
              i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT,
              (i0 + (size_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT
            }
          )));
    secret_as_ntt->data[i0] = uu____0;
  }
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cpa::deserialize_then_decompress_u::closure<Vector, K, CIPHERTEXT_SIZE, U_COMPRESSION_FACTOR>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_then_decompress_u.call_mut_35
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- U_COMPRESSION_FACTOR= 10
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_6c(
  void **_,
  size_t tupled_args
)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 10
*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_ef(Eurydice_arr_e2 a)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.data[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_public_integers_classify_27_39(LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS));
    decompressed = (decompressed << 1U) + ((int32_t)1 << (uint32_t)(int32_t)10);
    decompressed = decompressed >> (uint32_t)((int32_t)10 + (int32_t)1);
    a.data[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  return a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 10
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_ef(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(Eurydice_borrow_slice_u8 serialized)
{
  Eurydice_arr_b9 re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)20U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)20U, i0 * (size_t)20U + (size_t)20U }));
    Eurydice_arr_e2 coefficient = libcrux_ml_kem_vector_portable_deserialize_10_b8(bytes);
    Eurydice_arr_e2
    uu____0 = libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_ef(coefficient);
    re.data[i0] = uu____0;
  }
  return re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_0a(
  Eurydice_borrow_slice_u8 serialized
)
{
  return libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(serialized);
}

typedef struct libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2_s
{
  Eurydice_arr_e2 fst;
  Eurydice_arr_e2 snd;
}
libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2;

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_layer_int_vec_step
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
libcrux_ml_kem_ntt_ntt_layer_int_vec_step_ea(
  Eurydice_arr_e2 a,
  Eurydice_arr_e2 b,
  int16_t zeta_r
)
{
  Eurydice_arr_e2
  t = libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(b, zeta_r);
  b = libcrux_ml_kem_vector_portable_sub_b8(a, &t);
  a = libcrux_ml_kem_vector_portable_add_b8(a, &t);
  return ((libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2){ a, b });
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_4_plus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(
  size_t *zeta_i,
  Eurydice_arr_b9 *re,
  size_t layer,
  size_t _initial_coefficient_bound
)
{
  size_t step = (size_t)1U << (uint32_t)layer;
  for (size_t i0 = (size_t)0U; i0 < (size_t)128U >> (uint32_t)layer; i0++)
  {
    size_t round = i0;
    zeta_i[0U] = zeta_i[0U] + (size_t)1U;
    size_t offset = round * step * (size_t)2U;
    size_t offset_vec = offset / (size_t)16U;
    size_t step_vec = step / (size_t)16U;
    for (size_t i = offset_vec; i < offset_vec + step_vec; i++)
    {
      size_t j = i;
      libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
      uu____0 =
        libcrux_ml_kem_ntt_ntt_layer_int_vec_step_ea(re->data[j],
          re->data[j + step_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_e2 x = uu____0.fst;
      Eurydice_arr_e2 y = uu____0.snd;
      re->data[j] = x;
      re->data[j + step_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ntt_ntt_at_layer_3_ea(
  size_t *zeta_i,
  Eurydice_arr_b9 *re,
  size_t _initial_coefficient_bound
)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t round = i;
    zeta_i[0U] = zeta_i[0U] + (size_t)1U;
    Eurydice_arr_e2
    uu____0 =
      libcrux_ml_kem_vector_portable_ntt_layer_3_step_b8(re->data[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->data[round] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ntt_ntt_at_layer_2_ea(
  size_t *zeta_i,
  Eurydice_arr_b9 *re,
  size_t _initial_coefficient_bound
)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t round = i;
    zeta_i[0U] = zeta_i[0U] + (size_t)1U;
    re->data[round] =
      libcrux_ml_kem_vector_portable_ntt_layer_2_step_b8(re->data[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (size_t)1U));
    zeta_i[0U] = zeta_i[0U] + (size_t)1U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ntt_ntt_at_layer_1_ea(
  size_t *zeta_i,
  Eurydice_arr_b9 *re,
  size_t _initial_coefficient_bound
)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t round = i;
    zeta_i[0U] = zeta_i[0U] + (size_t)1U;
    re->data[round] =
      libcrux_ml_kem_vector_portable_ntt_layer_1_step_b8(re->data[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (size_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (size_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (size_t)3U));
    zeta_i[0U] = zeta_i[0U] + (size_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(Eurydice_arr_b9 *myself)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2 uu____0 = libcrux_ml_kem_vector_portable_barrett_reduce_b8(myself->data[i0]);
    myself->data[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(Eurydice_arr_b9 *self)
{
  libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(self);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_vector_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- VECTOR_U_COMPRESSION_FACTOR= 10
*/
static KRML_MUSTINLINE void libcrux_ml_kem_ntt_ntt_vector_u_0a(Eurydice_arr_b9 *re)
{
  size_t zeta_i = (size_t)0U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)7U, (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)6U, (size_t)2U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)5U, (size_t)3U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)4U, (size_t)4U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (size_t)5U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (size_t)6U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (size_t)7U * (size_t)3328U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
 Call [`deserialize_then_decompress_ring_element_u`] on each ring element
 in the `ciphertext`.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_then_decompress_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- U_COMPRESSION_FACTOR= 10
*/
static KRML_MUSTINLINE Eurydice_arr_1d
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_6c(const Eurydice_arr_2c *ciphertext)
{
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] =
      libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_6c(&lvalue,
        i);
  }
  Eurydice_arr_1d u_as_ntt = arr_struct;
  for
  (size_t
    i = (size_t)0U;
    i <
      (size_t)1088U /
        (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (size_t)10U / (size_t)8U);
    i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    u_bytes =
      Eurydice_array_to_subslice_shared_364(ciphertext,
        (
          (core_ops_range_Range_08){
            i0 * (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (size_t)10U / (size_t)8U),
            i0 * (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (size_t)10U / (size_t)8U)
            + LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (size_t)10U / (size_t)8U
          }
        ));
    u_as_ntt.data[i0] =
      libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_0a(u_bytes);
    libcrux_ml_kem_ntt_ntt_vector_u_0a(&u_as_ntt.data[i0]);
  }
  return u_as_ntt;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 4
*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_d1(Eurydice_arr_e2 a)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.data[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_public_integers_classify_27_39(LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS));
    decompressed = (decompressed << 1U) + ((int32_t)1 << (uint32_t)(int32_t)4);
    decompressed = decompressed >> (uint32_t)((int32_t)4 + (int32_t)1);
    a.data[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  return a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 4
*/
static inline Eurydice_arr_e2
libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_d1(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(Eurydice_borrow_slice_u8 serialized)
{
  Eurydice_arr_b9 re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)8U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)8U, i0 * (size_t)8U + (size_t)8U }));
    Eurydice_arr_e2 coefficient = libcrux_ml_kem_vector_portable_deserialize_4_b8(bytes);
    Eurydice_arr_e2
    uu____0 = libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_d1(coefficient);
    re.data[i0] = uu____0;
  }
  return re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_89(
  Eurydice_borrow_slice_u8 serialized
)
{
  return libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(serialized);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static inline Eurydice_arr_b9 libcrux_ml_kem_polynomial_ZERO_ea(void)
{
  Eurydice_arr_b9 lit;
  Eurydice_arr_e2 repeat_expression[16U];
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    repeat_expression[i] = libcrux_ml_kem_vector_portable_ZERO_b8();
  }
  memcpy(lit.data, repeat_expression, (size_t)16U * sizeof (Eurydice_arr_e2));
  return lit;
}

/**
 Given two `KyberPolynomialRingElement`s in their NTT representations,
 compute their product. Given two polynomials in the NTT domain `f^` and `ĵ`,
 the `iᵗʰ` coefficient of the product `k̂` is determined by the calculation:

 ```plaintext
 ĥ[2·i] + ĥ[2·i + 1]X = (f^[2·i] + f^[2·i + 1]X)·(ĝ[2·i] + ĝ[2·i + 1]X) mod (X² - ζ^(2·BitRev₇(i) + 1))
 ```

 This function almost implements <strong>Algorithm 10</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input: Two arrays fˆ ∈ ℤ₂₅₆ and ĝ ∈ ℤ₂₅₆.
 Output: An array ĥ ∈ ℤq.

 for(i ← 0; i < 128; i++)
     (ĥ[2i], ĥ[2i+1]) ← BaseCaseMultiply(fˆ[2i], fˆ[2i+1], ĝ[2i], ĝ[2i+1], ζ^(2·BitRev₇(i) + 1))
 end for
 return ĥ
 ```
 We say "almost" because the coefficients of the ring element output by
 this function are in the Montgomery domain.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_ntt_multiply_ea(
  const Eurydice_arr_b9 *myself,
  const Eurydice_arr_b9 *rhs
)
{
  Eurydice_arr_b9 out = libcrux_ml_kem_polynomial_ZERO_ea();
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    uu____0 =
      libcrux_ml_kem_vector_portable_ntt_multiply_b8(&myself->data[i0],
        &rhs->data[i0],
        libcrux_ml_kem_polynomial_zeta((size_t)64U + (size_t)4U * i0),
        libcrux_ml_kem_polynomial_zeta((size_t)64U + (size_t)4U * i0 + (size_t)1U),
        libcrux_ml_kem_polynomial_zeta((size_t)64U + (size_t)4U * i0 + (size_t)2U),
        libcrux_ml_kem_polynomial_zeta((size_t)64U + (size_t)4U * i0 + (size_t)3U));
    out.data[i0] = uu____0;
  }
  return out;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(
  const Eurydice_arr_b9 *self,
  const Eurydice_arr_b9 *rhs
)
{
  return libcrux_ml_kem_polynomial_ntt_multiply_ea(self, rhs);
}

/**
 Given two polynomial ring elements `lhs` and `rhs`, compute the pointwise
 sum of their constituent coefficients.
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_to_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_add_to_ring_element_1b(
  Eurydice_arr_b9 *myself,
  const Eurydice_arr_b9 *rhs
)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    uu____0 = libcrux_ml_kem_vector_portable_add_b8(myself->data[i0], &rhs->data[i0]);
    myself->data[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_to_ring_element_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_add_to_ring_element_d6_1b(
  Eurydice_arr_b9 *self,
  const Eurydice_arr_b9 *rhs
)
{
  libcrux_ml_kem_polynomial_add_to_ring_element_1b(self, rhs);
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(size_t *zeta_i, Eurydice_arr_b9 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t round = i;
    zeta_i[0U] = zeta_i[0U] - (size_t)1U;
    re->data[round] =
      libcrux_ml_kem_vector_portable_inv_ntt_layer_1_step_b8(re->data[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (size_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (size_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (size_t)3U));
    zeta_i[0U] = zeta_i[0U] - (size_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(size_t *zeta_i, Eurydice_arr_b9 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t round = i;
    zeta_i[0U] = zeta_i[0U] - (size_t)1U;
    re->data[round] =
      libcrux_ml_kem_vector_portable_inv_ntt_layer_2_step_b8(re->data[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (size_t)1U));
    zeta_i[0U] = zeta_i[0U] - (size_t)1U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(size_t *zeta_i, Eurydice_arr_b9 *re)
{
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t round = i;
    zeta_i[0U] = zeta_i[0U] - (size_t)1U;
    Eurydice_arr_e2
    uu____0 =
      libcrux_ml_kem_vector_portable_inv_ntt_layer_3_step_b8(re->data[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->data[round] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.inv_ntt_layer_int_vec_step_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_step_reduce_ea(
  Eurydice_arr_e2 a,
  Eurydice_arr_e2 b,
  int16_t zeta_r
)
{
  Eurydice_arr_e2 a_minus_b = libcrux_ml_kem_vector_portable_sub_b8(b, &a);
  a =
    libcrux_ml_kem_vector_portable_barrett_reduce_b8(libcrux_ml_kem_vector_portable_add_b8(a, &b));
  b = libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(a_minus_b, zeta_r);
  return ((libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2){ a, b });
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_4_plus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(
  size_t *zeta_i,
  Eurydice_arr_b9 *re,
  size_t layer
)
{
  size_t step = (size_t)1U << (uint32_t)layer;
  for (size_t i0 = (size_t)0U; i0 < (size_t)128U >> (uint32_t)layer; i0++)
  {
    size_t round = i0;
    zeta_i[0U] = zeta_i[0U] - (size_t)1U;
    size_t offset = round * step * (size_t)2U;
    size_t offset_vec = offset / LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR;
    size_t step_vec = step / LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR;
    for (size_t i = offset_vec; i < offset_vec + step_vec; i++)
    {
      size_t j = i;
      libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
      uu____0 =
        libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_step_reduce_ea(re->data[j],
          re->data[j + step_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_e2 x = uu____0.fst;
      Eurydice_arr_e2 y = uu____0.snd;
      re->data[j] = x;
      re->data[j + step_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_montgomery
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_1b(Eurydice_arr_b9 *re)
{
  size_t zeta_i = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (size_t)2U;
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)4U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)5U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)6U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)7U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_subtract_reduce_ea(const Eurydice_arr_b9 *myself, Eurydice_arr_b9 b)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient_normal_form =
      libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(b.data[i0],
        (int16_t)1441);
    Eurydice_arr_e2
    diff = libcrux_ml_kem_vector_portable_sub_b8(myself->data[i0], &coefficient_normal_form);
    Eurydice_arr_e2 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(diff);
    b.data[i0] = red;
  }
  return b;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_subtract_reduce_d6_ea(const Eurydice_arr_b9 *self, Eurydice_arr_b9 b)
{
  return libcrux_ml_kem_polynomial_subtract_reduce_ea(self, b);
}

/**
 The following functions compute various expressions involving
 vectors and matrices. The computation of these expressions has been
 abstracted away into these functions in order to save on loop iterations.
 Compute v − InverseNTT(sᵀ ◦ NTT(u))
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_matrix_compute_message_1b(
  const Eurydice_arr_b9 *v,
  const Eurydice_arr_1d *secret_as_ntt,
  const Eurydice_arr_1d *u_as_ntt
)
{
  Eurydice_arr_b9 result = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9
    product =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&secret_as_ntt->data[i0],
        &u_as_ntt->data[i0]);
    libcrux_ml_kem_polynomial_add_to_ring_element_d6_1b(&result, &product);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_1b(&result);
  return libcrux_ml_kem_polynomial_subtract_reduce_d6_ea(v, result);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.to_unsigned_field_modulus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_to_unsigned_representative_b8(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_serialize_compress_then_serialize_message_ea(Eurydice_arr_b9 re)
{
  Eurydice_arr_600 serialized = { { 0U } };
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient = libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re.data[i0]);
    Eurydice_arr_e2
    coefficient_compressed = libcrux_ml_kem_vector_portable_compress_1_b8(coefficient);
    Eurydice_array_u8x2
    bytes = libcrux_ml_kem_vector_portable_serialize_1_b8(coefficient_compressed);
    Eurydice_slice_copy(Eurydice_array_to_subslice_mut_364(&serialized,
        ((core_ops_range_Range_08){ (size_t)2U * i0, (size_t)2U * i0 + (size_t)2U })),
      Eurydice_array_to_slice_shared_26(&bytes),
      uint8_t);
  }
  return serialized;
}

/**
 This function implements <strong>Algorithm 14</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE decryption algorithm.

 Algorithm 14 is reproduced below:

 ```plaintext
 Input: decryption key dkₚₖₑ ∈ 𝔹^{384k}.
 Input: ciphertext c ∈ 𝔹^{32(dᵤk + dᵥ)}.
 Output: message m ∈ 𝔹^{32}.

 c₁ ← c[0 : 32dᵤk]
 c₂ ← c[32dᵤk : 32(dᵤk + dᵥ)]
 u ← (Decompress_){dᵤ}((ByteDecode_){dᵤ}(c₁))
 v ← (Decompress_){dᵥ}((ByteDecode_){dᵥ}(c₂))
 ŝ ← ByteDecode₁₂(dkₚₖₑ)
 w ← v - NTT-¹(ŝᵀ ◦ NTT(u))
 m ← ByteEncode₁(Compress₁(w))
 return m
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_ind_cpa_decrypt_unpacked_42(
  const Eurydice_arr_1d *secret_key,
  const Eurydice_arr_2c *ciphertext
)
{
  Eurydice_arr_1d u_as_ntt = libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_6c(ciphertext);
  Eurydice_arr_b9
  v =
    libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_89(Eurydice_array_to_subslice_from_shared_8c0(ciphertext,
        (size_t)960U));
  Eurydice_arr_b9 message = libcrux_ml_kem_matrix_compute_message_1b(&v, secret_key, &u_as_ntt);
  return libcrux_ml_kem_serialize_compress_then_serialize_message_ea(message);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_ind_cpa_decrypt_42(
  Eurydice_borrow_slice_u8 secret_key,
  const Eurydice_arr_2c *ciphertext
)
{
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] = libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_42(&lvalue, i);
  }
  Eurydice_arr_1d secret_key_unpacked = arr_struct;
  libcrux_ml_kem_ind_cpa_deserialize_vector_1b(secret_key, &secret_key_unpacked);
  return libcrux_ml_kem_ind_cpa_decrypt_unpacked_42(&secret_key_unpacked, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.G_4a
with const generics
- K= 3
*/
static inline Eurydice_arr_060
libcrux_ml_kem_hash_functions_portable_G_4a_e0(Eurydice_borrow_slice_u8 input)
{
  return libcrux_ml_kem_hash_functions_portable_G(input);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 32
*/
static inline Eurydice_arr_600
libcrux_ml_kem_hash_functions_portable_PRF_9e(Eurydice_borrow_slice_u8 input)
{
  Eurydice_arr_600 digest = { { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_6e(&digest), input);
  return digest;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF_4a
with const generics
- K= 3
- LEN= 32
*/
static inline Eurydice_arr_600
libcrux_ml_kem_hash_functions_portable_PRF_4a_41(Eurydice_borrow_slice_u8 input)
{
  return libcrux_ml_kem_hash_functions_portable_PRF_9e(input);
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_1d
with const generics
- $3size_t
*/
typedef struct Eurydice_arr_dd0_s { Eurydice_arr_1d data[3U]; } Eurydice_arr_dd0;

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.IndCpaPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
typedef struct libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0_s
{
  Eurydice_arr_1d t_as_ntt;
  Eurydice_arr_600 seed_for_A;
  Eurydice_arr_dd0 A;
}
libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0;

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_8b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
libcrux_ml_kem_ind_cpa_unpacked_default_8b_1b(void)
{
  Eurydice_arr_1d uu____0;
  Eurydice_arr_b9 repeat_expression0[3U];
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    repeat_expression0[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  memcpy(uu____0.data, repeat_expression0, (size_t)3U * sizeof (Eurydice_arr_b9));
  Eurydice_arr_600 uu____1 = { { 0U } };
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 lit0;
  lit0.t_as_ntt = uu____0;
  lit0.seed_for_A = uu____1;
  Eurydice_arr_1d repeat_expression1[3U];
  for (size_t i0 = (size_t)0U; i0 < (size_t)3U; i0++)
  {
    Eurydice_arr_1d lit;
    Eurydice_arr_b9 repeat_expression[3U];
    for (size_t i = (size_t)0U; i < (size_t)3U; i++)
    {
      repeat_expression[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    }
    memcpy(lit.data, repeat_expression, (size_t)3U * sizeof (Eurydice_arr_b9));
    repeat_expression1[i0] = lit;
  }
  memcpy(lit0.A.data, repeat_expression1, (size_t)3U * sizeof (Eurydice_arr_1d));
  return lit0;
}

/**
 Only use with public values.

 This MUST NOT be used with secret inputs, like its caller `deserialize_ring_elements_reduced`.
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_reduced_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_to_reduced_ring_element_ea(
  Eurydice_borrow_slice_u8 serialized
)
{
  Eurydice_arr_b9 re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < serialized.meta / (size_t)24U; i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_7e(serialized,
        ((core_ops_range_Range_08){ i0 * (size_t)24U, i0 * (size_t)24U + (size_t)24U }));
    Eurydice_arr_e2 coefficient = libcrux_ml_kem_vector_portable_deserialize_12_b8(bytes);
    Eurydice_arr_e2 uu____0 = libcrux_ml_kem_vector_portable_cond_subtract_3329_b8(coefficient);
    re.data[i0] = uu____0;
  }
  return re;
}

/**
 See [deserialize_ring_elements_reduced_out].
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_1b(
  Eurydice_borrow_slice_u8 public_key,
  Eurydice_arr_1d *deserialized_pk
)
{
  for
  (size_t
    i = (size_t)0U;
    i < public_key.meta / LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT;
    i++)
  {
    size_t i0 = i;
    Eurydice_borrow_slice_u8
    ring_element =
      Eurydice_slice_subslice_shared_7e(public_key,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT,
            i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT +
              LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT
          }
        ));
    Eurydice_arr_b9
    uu____0 = libcrux_ml_kem_serialize_deserialize_to_reduced_ring_element_ea(ring_element);
    deserialized_pk->data[i0] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final
with const generics
- K= 3
*/
static inline Eurydice_arr_e4
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_e0(
  const Eurydice_arr_c31 *input
)
{
  Eurydice_arr_e4 shake128_state;
  Eurydice_arr_26 repeat_expression[3U];
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    repeat_expression[i] = libcrux_sha3_portable_incremental_shake128_init();
  }
  memcpy(shake128_state.data, repeat_expression, (size_t)3U * sizeof (Eurydice_arr_26));
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_absorb_final(&shake128_state.data[i0],
      Eurydice_array_to_slice_shared_8d(&input->data[i0]));
  }
  return shake128_state;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final_4a
with const generics
- K= 3
*/
static inline Eurydice_arr_e4
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_e0(
  const Eurydice_arr_c31 *input
)
{
  return libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_e0(input);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks
with const generics
- K= 3
*/
static inline Eurydice_arr_e6
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_e0(
  Eurydice_arr_e4 *st
)
{
  Eurydice_arr_e6 out = { { { { 0U } }, { { 0U } }, { { 0U } } } };
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(&st->data[i0],
      Eurydice_array_to_slice_mut_85(&out.data[i0]));
  }
  return out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks_4a
with const generics
- K= 3
*/
static inline Eurydice_arr_e6
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_4a_e0(
  Eurydice_arr_e4 *self
)
{
  return libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_e0(self);
}

/**
 If `bytes` contains a set of uniformly random bytes, this function
 uniformly samples a ring element `â` that is treated as being the NTT representation
 of the corresponding polynomial `a`.

 Since rejection sampling is used, it is possible the supplied bytes are
 not enough to sample the element, in which case an `Err` is returned and the
 caller must try again with a fresh set of bytes.

 This function <strong>partially</strong> implements <strong>Algorithm 6</strong> of the NIST FIPS 203 standard,
 We say "partially" because this implementation only accepts a finite set of
 bytes as input and returns an error if the set is not enough; Algorithm 6 of
 the FIPS 203 standard on the other hand samples from an infinite stream of bytes
 until the ring element is filled. Algorithm 6 is reproduced below:

 ```plaintext
 Input: byte stream B ∈ 𝔹*.
 Output: array â ∈ ℤ₂₅₆.

 i ← 0
 j ← 0
 while j < 256 do
     d₁ ← B[i] + 256·(B[i+1] mod 16)
     d₂ ← ⌊B[i+1]/16⌋ + 16·B[i+2]
     if d₁ < q then
         â[j] ← d₁
         j ← j + 1
     end if
     if d₂ < q and j < 256 then
         â[j] ← d₂
         j ← j + 1
     end if
     i ← i + 3
 end while
 return â
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_uniform_distribution_next
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- N= 504
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_uniform_distribution_next_89(
  const Eurydice_arr_e6 *randomness,
  Eurydice_arr_c8 *sampled_coefficients,
  Eurydice_arr_dd1 *out
)
{
  for (size_t i0 = (size_t)0U; i0 < (size_t)3U; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)504U / (size_t)24U; i++)
    {
      size_t r = i;
      if (sampled_coefficients->data[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        size_t
        sampled =
          libcrux_ml_kem_vector_portable_rej_sample_b8(Eurydice_array_to_subslice_shared_365(&randomness->data[i1],
              ((core_ops_range_Range_08){ r * (size_t)24U, r * (size_t)24U + (size_t)24U })),
            Eurydice_array_to_subslice_mut_85(&out->data[i1],
              (
                (core_ops_range_Range_08){
                  sampled_coefficients->data[i1],
                  sampled_coefficients->data[i1] + (size_t)16U
                }
              )));
        size_t uu____0 = i1;
        sampled_coefficients->data[uu____0] = sampled_coefficients->data[uu____0] + sampled;
      }
    }
  }
  bool done = true;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    if (sampled_coefficients->data[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
    {
      sampled_coefficients->data[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT;
    }
    else
    {
      done = false;
    }
  }
  return done;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block
with const generics
- K= 3
*/
static inline Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_next_block_e0(Eurydice_arr_e4 *st)
{
  Eurydice_arr_7e out = { { { { 0U } }, { { 0U } }, { { 0U } } } };
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_next_block(&st->data[i0],
      Eurydice_array_to_slice_mut_7b(&out.data[i0]));
  }
  return out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block_4a
with const generics
- K= 3
*/
static inline Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_next_block_4a_e0(Eurydice_arr_e4 *self)
{
  return libcrux_ml_kem_hash_functions_portable_shake128_squeeze_next_block_e0(self);
}

/**
 If `bytes` contains a set of uniformly random bytes, this function
 uniformly samples a ring element `â` that is treated as being the NTT representation
 of the corresponding polynomial `a`.

 Since rejection sampling is used, it is possible the supplied bytes are
 not enough to sample the element, in which case an `Err` is returned and the
 caller must try again with a fresh set of bytes.

 This function <strong>partially</strong> implements <strong>Algorithm 6</strong> of the NIST FIPS 203 standard,
 We say "partially" because this implementation only accepts a finite set of
 bytes as input and returns an error if the set is not enough; Algorithm 6 of
 the FIPS 203 standard on the other hand samples from an infinite stream of bytes
 until the ring element is filled. Algorithm 6 is reproduced below:

 ```plaintext
 Input: byte stream B ∈ 𝔹*.
 Output: array â ∈ ℤ₂₅₆.

 i ← 0
 j ← 0
 while j < 256 do
     d₁ ← B[i] + 256·(B[i+1] mod 16)
     d₂ ← ⌊B[i+1]/16⌋ + 16·B[i+2]
     if d₁ < q then
         â[j] ← d₁
         j ← j + 1
     end if
     if d₂ < q and j < 256 then
         â[j] ← d₂
         j ← j + 1
     end if
     i ← i + 3
 end while
 return â
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_uniform_distribution_next
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- N= 168
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_uniform_distribution_next_890(
  const Eurydice_arr_7e *randomness,
  Eurydice_arr_c8 *sampled_coefficients,
  Eurydice_arr_dd1 *out
)
{
  for (size_t i0 = (size_t)0U; i0 < (size_t)3U; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)168U / (size_t)24U; i++)
    {
      size_t r = i;
      if (sampled_coefficients->data[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        size_t
        sampled =
          libcrux_ml_kem_vector_portable_rej_sample_b8(Eurydice_array_to_subslice_shared_366(&randomness->data[i1],
              ((core_ops_range_Range_08){ r * (size_t)24U, r * (size_t)24U + (size_t)24U })),
            Eurydice_array_to_subslice_mut_85(&out->data[i1],
              (
                (core_ops_range_Range_08){
                  sampled_coefficients->data[i1],
                  sampled_coefficients->data[i1] + (size_t)16U
                }
              )));
        size_t uu____0 = i1;
        sampled_coefficients->data[uu____0] = sampled_coefficients->data[uu____0] + sampled;
      }
    }
  }
  bool done = true;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    if (sampled_coefficients->data[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
    {
      sampled_coefficients->data[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT;
    }
    else
    {
      done = false;
    }
  }
  return done;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_from_i16_array_ea(Eurydice_borrow_slice_i16 a)
{
  Eurydice_arr_b9 result = libcrux_ml_kem_polynomial_ZERO_ea();
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    uu____0 =
      libcrux_ml_kem_vector_portable_from_i16_array_b8(Eurydice_slice_subslice_shared_76(a,
          ((core_ops_range_Range_08){ i0 * (size_t)16U, (i0 + (size_t)1U) * (size_t)16U })));
    result.data[i0] = uu____0;
  }
  return result;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_borrow_slice_i16 a)
{
  return libcrux_ml_kem_polynomial_from_i16_array_ea(a);
}

/**
This function found in impl {core::ops::function::FnMut<(@Array<i16, 272usize>), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::sampling::sample_from_xof::closure<Vector, Hasher, K>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof.call_mut_e7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_sampling_sample_from_xof_call_mut_e7_2b(void **_, Eurydice_arr_a00 tupled_args)
{
  Eurydice_arr_a00 s = tupled_args;
  return
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_to_subslice_shared_850(&s,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)256U })));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_1d
libcrux_ml_kem_sampling_sample_from_xof_2b(const Eurydice_arr_c31 *seeds)
{
  Eurydice_arr_c8 sampled_coefficients = { { 0U } };
  Eurydice_arr_dd1 out = { { { { 0U } }, { { 0U } }, { { 0U } } } };
  Eurydice_arr_e4
  xof_state = libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_e0(seeds);
  Eurydice_arr_e6
  randomness0 =
    libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_4a_e0(&xof_state);
  bool
  done =
    libcrux_ml_kem_sampling_sample_from_uniform_distribution_next_89(&randomness0,
      &sampled_coefficients,
      &out);
  while (true)
  {
    if (done)
    {
      break;
    }
    else
    {
      Eurydice_arr_7e
      randomness =
        libcrux_ml_kem_hash_functions_portable_shake128_squeeze_next_block_4a_e0(&xof_state);
      done =
        libcrux_ml_kem_sampling_sample_from_uniform_distribution_next_890(&randomness,
          &sampled_coefficients,
          &out);
    }
  }
  Eurydice_arr_1d arr_mapped_str;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_mapped_str.data[i] =
      libcrux_ml_kem_sampling_sample_from_xof_call_mut_e7_2b(&lvalue,
        out.data[i]);
  }
  return arr_mapped_str;
}

/**
A monomorphic instance of libcrux_ml_kem.matrix.sample_matrix_A
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_matrix_sample_matrix_A_2b(
  Eurydice_arr_dd0 *A_transpose,
  const Eurydice_arr_48 *seed,
  bool transpose
)
{
  for (size_t i0 = (size_t)0U; i0 < (size_t)3U; i0++)
  {
    size_t i1 = i0;
    Eurydice_arr_c31 seeds;
    Eurydice_arr_48 repeat_expression[3U];
    for (size_t i = (size_t)0U; i < (size_t)3U; i++)
    {
      repeat_expression[i] =
        core_array__core__clone__Clone_for__Array_T__N___clone((size_t)34U,
          seed,
          uint8_t,
          Eurydice_arr_48);
    }
    memcpy(seeds.data, repeat_expression, (size_t)3U * sizeof (Eurydice_arr_48));
    for (size_t i = (size_t)0U; i < (size_t)3U; i++)
    {
      size_t j = i;
      seeds.data[j].data[32U] = (uint8_t)i1;
      seeds.data[j].data[33U] = (uint8_t)j;
    }
    Eurydice_arr_1d sampled = libcrux_ml_kem_sampling_sample_from_xof_2b(&seeds);
    for (size_t i = (size_t)0U; i < (size_t)3U; i++)
    {
      size_t j = i;
      Eurydice_arr_b9 sample = sampled.data[j];
      if (transpose)
      {
        A_transpose->data[j].data[i1] = sample;
      }
      else
      {
        A_transpose->data[i1].data[j] = sample;
      }
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key_mut
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_build_unpacked_public_key_mut_3f(
  Eurydice_borrow_slice_u8 public_key,
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 *unpacked_public_key
)
{
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_1b(Eurydice_slice_subslice_to_shared_c6(public_key,
      (size_t)1152U),
    &unpacked_public_key->t_as_ntt);
  Eurydice_borrow_slice_u8
  seed = Eurydice_slice_subslice_from_shared_6b(public_key, (size_t)1152U);
  Eurydice_arr_dd0 *uu____0 = &unpacked_public_key->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_48 lvalue = libcrux_ml_kem_utils_into_padded_array_b6(seed);
  libcrux_ml_kem_matrix_sample_matrix_A_2b(uu____0, &lvalue, false);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
static KRML_MUSTINLINE libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
libcrux_ml_kem_ind_cpa_build_unpacked_public_key_3f(Eurydice_borrow_slice_u8 public_key)
{
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
  unpacked_public_key = libcrux_ml_kem_ind_cpa_unpacked_default_8b_1b();
  libcrux_ml_kem_ind_cpa_build_unpacked_public_key_mut_3f(public_key, &unpacked_public_key);
  return unpacked_public_key;
}

/**
A monomorphic instance of K.
with types Eurydice_arr_1d, libcrux_ml_kem_polynomial_PolynomialRingElement_1d

*/
typedef struct tuple_ac_s
{
  Eurydice_arr_1d fst;
  Eurydice_arr_b9 snd;
}
tuple_ac;

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::ind_cpa::encrypt_c1::closure<Vector, Hasher, K, C1_LEN, U_COMPRESSION_FACTOR, BLOCK_LEN, ETA1, ETA1_RANDOMNESS_SIZE, ETA2, ETA2_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1.call_mut_f1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_85(void **_, size_t tupled_args)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN
with const generics
- K= 3
- LEN= 128
*/
static inline Eurydice_arr_ad0
libcrux_ml_kem_hash_functions_portable_PRFxN_41(const Eurydice_arr_b1 *input)
{
  Eurydice_arr_ad0 out = { { { { 0U } }, { { 0U } }, { { 0U } } } };
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_18(&out.data[i0]),
      Eurydice_array_to_slice_shared_61(&input->data[i0]));
  }
  return out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN_4a
with const generics
- K= 3
- LEN= 128
*/
static inline Eurydice_arr_ad0
libcrux_ml_kem_hash_functions_portable_PRFxN_4a_41(const Eurydice_arr_b1 *input)
{
  return libcrux_ml_kem_hash_functions_portable_PRFxN_41(input);
}

/**
 Given a series of uniformly random bytes in `randomness`, for some number `eta`,
 the `(sample_from_binomial_distribution_){eta}` functions sample
 a ring element from a binomial distribution centered at 0 that uses two sets
 of `eta` coin flips. If, for example,
 `eta = ETA`, each ring coefficient is a value `v` such
 such that `v ∈ {-ETA, -ETA + 1, ..., 0, ..., ETA + 1, ETA}` and:

 ```plaintext
 - If v < 0, Pr[v] = Pr[-v]
 - If v >= 0, Pr[v] = BINOMIAL_COEFFICIENT(2 * ETA; ETA - v) / 2 ^ (2 * ETA)
 ```

 The values `v < 0` are mapped to the appropriate `KyberFieldElement`.

 The expected value is:

 ```plaintext
 E[X] = (-ETA)Pr[-ETA] + (-(ETA - 1))Pr[-(ETA - 1)] + ... + (ETA - 1)Pr[ETA - 1] + (ETA)Pr[ETA]
      = 0 since Pr[-v] = Pr[v] when v < 0.
 ```

 And the variance is:

 ```plaintext
 Var(X) = E[(X - E[X])^2]
        = E[X^2]
        = sum_(v=-ETA to ETA)v^2 * (BINOMIAL_COEFFICIENT(2 * ETA; ETA - v) / 2^(2 * ETA))
        = ETA / 2
 ```

 This function implements <strong>Algorithm 7</strong> of the NIST FIPS 203 standard, which is
 reproduced below:

 ```plaintext
 Input: byte array B ∈ 𝔹^{64η}.
 Output: array f ∈ ℤ₂₅₆.

 b ← BytesToBits(B)
 for (i ← 0; i < 256; i++)
     x ← ∑(j=0 to η - 1) b[2iη + j]
     y ← ∑(j=0 to η - 1) b[2iη + η + j]
     f[i] ← x−y mod q
 end for
 return f
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_sampling_sample_from_binomial_distribution_2_ea(
  Eurydice_borrow_slice_u8 randomness
)
{
  Eurydice_arr_c1 sampled_i16s = { { 0U } };
  for (size_t i0 = (size_t)0U; i0 < randomness.meta / (size_t)4U; i0++)
  {
    size_t chunk_number = i0;
    Eurydice_borrow_slice_u8
    byte_chunk =
      Eurydice_slice_subslice_shared_7e(randomness,
        (
          (core_ops_range_Range_08){
            chunk_number * (size_t)4U,
            chunk_number * (size_t)4U + (size_t)4U
          }
        ));
    uint32_t
    random_bits_as_u32 =
      (((uint32_t)byte_chunk.ptr[0U] | (uint32_t)byte_chunk.ptr[1U] << 8U) |
        (uint32_t)byte_chunk.ptr[2U] << 16U)
      | (uint32_t)byte_chunk.ptr[3U] << 24U;
    uint32_t even_bits = random_bits_as_u32 & 1431655765U;
    uint32_t odd_bits = random_bits_as_u32 >> 1U & 1431655765U;
    uint32_t coin_toss_outcomes = even_bits + odd_bits;
    for (uint32_t i = 0U; i < 32U / 4U; i++)
    {
      uint32_t outcome_set = i;
      uint32_t outcome_set0 = outcome_set * 4U;
      int16_t outcome_1 = (int16_t)(coin_toss_outcomes >> (uint32_t)outcome_set0 & 3U);
      int16_t outcome_2 = (int16_t)(coin_toss_outcomes >> (uint32_t)(outcome_set0 + 2U) & 3U);
      size_t offset = (size_t)(outcome_set0 >> 2U);
      sampled_i16s.data[(size_t)8U * chunk_number + offset] = outcome_1 - outcome_2;
    }
  }
  return
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_to_slice_shared_1a(&sampled_i16s));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- ETA= 2
*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_sampling_sample_from_binomial_distribution_a0(
  Eurydice_borrow_slice_u8 randomness
)
{
  return libcrux_ml_kem_sampling_sample_from_binomial_distribution_2_ea(randomness);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void libcrux_ml_kem_ntt_ntt_at_layer_7_ea(Eurydice_arr_b9 *re)
{
  size_t step = LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT / (size_t)2U;
  for (size_t i = (size_t)0U; i < step; i++)
  {
    size_t j = i;
    Eurydice_arr_e2
    t = libcrux_ml_kem_vector_portable_multiply_by_constant_b8(re->data[j + step], (int16_t)-1600);
    re->data[j + step] = libcrux_ml_kem_vector_portable_sub_b8(re->data[j], &t);
    Eurydice_arr_e2 uu____1 = libcrux_ml_kem_vector_portable_add_b8(re->data[j], &t);
    re->data[j] = uu____1;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_binomially_sampled_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(Eurydice_arr_b9 *re)
{
  libcrux_ml_kem_ntt_ntt_at_layer_7_ea(re);
  size_t zeta_i = (size_t)1U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (size_t)6U, (size_t)11207U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (size_t)5U,
    (size_t)11207U + (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (size_t)4U,
    (size_t)11207U + (size_t)2U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (size_t)11207U + (size_t)3U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (size_t)11207U + (size_t)4U * (size_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (size_t)11207U + (size_t)5U * (size_t)3328U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
 Sample a vector of ring elements from a centered binomial distribution and
 convert them into their NTT representations.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.sample_vector_cbd_then_ntt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- ETA= 2
- ETA_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_3b(
  Eurydice_arr_1d *re_as_ntt,
  const Eurydice_arr_3e0 *prf_input,
  uint8_t domain_separator
)
{
  Eurydice_arr_b1 prf_inputs;
  Eurydice_arr_3e0 repeat_expression[3U];
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    repeat_expression[i] =
      core_array__core__clone__Clone_for__Array_T__N___clone((size_t)33U,
        prf_input,
        uint8_t,
        Eurydice_arr_3e0);
  }
  memcpy(prf_inputs.data, repeat_expression, (size_t)3U * sizeof (Eurydice_arr_3e0));
  domain_separator = libcrux_ml_kem_utils_prf_input_inc_e0(&prf_inputs, domain_separator);
  Eurydice_arr_ad0 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_41(&prf_inputs);
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_binomial_distribution_a0(Eurydice_array_to_slice_shared_18(&prf_outputs.data[i0]));
    re_as_ntt->data[i0] = uu____0;
    libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(&re_as_ntt->data[i0]);
  }
  return domain_separator;
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::ind_cpa::encrypt_c1::closure#1<Vector, Hasher, K, C1_LEN, U_COMPRESSION_FACTOR, BLOCK_LEN, ETA1, ETA1_RANDOMNESS_SIZE, ETA2, ETA2_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1.call_mut_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_85(void **_, size_t tupled_args)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
 Sample a vector of ring elements from a centered binomial distribution.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.sample_ring_element_cbd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- ETA2_RANDOMNESS_SIZE= 128
- ETA2= 2
*/
static KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_3b(
  const Eurydice_arr_3e0 *prf_input,
  uint8_t domain_separator,
  Eurydice_arr_1d *error_1
)
{
  Eurydice_arr_b1 prf_inputs;
  Eurydice_arr_3e0 repeat_expression[3U];
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    repeat_expression[i] =
      core_array__core__clone__Clone_for__Array_T__N___clone((size_t)33U,
        prf_input,
        uint8_t,
        Eurydice_arr_3e0);
  }
  memcpy(prf_inputs.data, repeat_expression, (size_t)3U * sizeof (Eurydice_arr_3e0));
  domain_separator = libcrux_ml_kem_utils_prf_input_inc_e0(&prf_inputs, domain_separator);
  Eurydice_arr_ad0 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_41(&prf_inputs);
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_binomial_distribution_a0(Eurydice_array_to_slice_shared_18(&prf_outputs.data[i0]));
    error_1->data[i0] = uu____0;
  }
  return domain_separator;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 128
*/
static inline Eurydice_arr_d1
libcrux_ml_kem_hash_functions_portable_PRF_a6(Eurydice_borrow_slice_u8 input)
{
  Eurydice_arr_d1 digest = { { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_18(&digest), input);
  return digest;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF_4a
with const generics
- K= 3
- LEN= 128
*/
static inline Eurydice_arr_d1
libcrux_ml_kem_hash_functions_portable_PRF_4a_410(Eurydice_borrow_slice_u8 input)
{
  return libcrux_ml_kem_hash_functions_portable_PRF_a6(input);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::matrix::compute_vector_u::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_vector_u.call_mut_a8
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_matrix_compute_vector_u_call_mut_a8_1b(void **_, size_t tupled_args)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_add_error_reduce_ea(
  Eurydice_arr_b9 *myself,
  const Eurydice_arr_b9 *error
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t j = i;
    Eurydice_arr_e2
    coefficient_normal_form =
      libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(myself->data[j],
        (int16_t)1441);
    Eurydice_arr_e2
    sum = libcrux_ml_kem_vector_portable_add_b8(coefficient_normal_form, &error->data[j]);
    Eurydice_arr_e2 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(sum);
    myself->data[j] = red;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_add_error_reduce_d6_ea(
  Eurydice_arr_b9 *self,
  const Eurydice_arr_b9 *error
)
{
  libcrux_ml_kem_polynomial_add_error_reduce_ea(self, error);
}

/**
 Compute u := InvertNTT(Aᵀ ◦ r̂) + e₁
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_vector_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_1d
libcrux_ml_kem_matrix_compute_vector_u_1b(
  const Eurydice_arr_dd0 *a_as_ntt,
  const Eurydice_arr_1d *r_as_ntt,
  const Eurydice_arr_1d *error_1
)
{
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] = libcrux_ml_kem_matrix_compute_vector_u_call_mut_a8_1b(&lvalue, i);
  }
  Eurydice_arr_1d result = arr_struct;
  for (size_t i0 = (size_t)0U; i0 < (size_t)3U; i0++)
  {
    size_t i1 = i0;
    const Eurydice_arr_1d *row = &a_as_ntt->data[i1];
    for (size_t i = (size_t)0U; i < (size_t)3U; i++)
    {
      size_t j = i;
      const Eurydice_arr_b9 *a_element = &row->data[j];
      Eurydice_arr_b9
      product = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(a_element, &r_as_ntt->data[j]);
      libcrux_ml_kem_polynomial_add_to_ring_element_d6_1b(&result.data[i1], &product);
    }
    libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_1b(&result.data[i1]);
    libcrux_ml_kem_polynomial_add_error_reduce_d6_ea(&result.data[i1], &error_1->data[i1]);
  }
  return result;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 10
*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_compress_compress_ef(Eurydice_arr_e2 a)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient((uint8_t)(int32_t)10,
          libcrux_secrets_int_as_u16_f5(a.data[i0])));
    a.data[i0] = uu____0;
  }
  return a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 10
*/
static inline Eurydice_arr_e2 libcrux_ml_kem_vector_portable_compress_b8_ef(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_compress_compress_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- OUT_LEN= 320
*/
static KRML_MUSTINLINE Eurydice_arr_b70
libcrux_ml_kem_serialize_compress_then_serialize_10_ff(const Eurydice_arr_b9 *re)
{
  Eurydice_arr_b70 serialized = { { 0U } };
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient =
      libcrux_ml_kem_vector_portable_compress_b8_ef(libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re->data[i0]));
    Eurydice_arr_dc bytes = libcrux_ml_kem_vector_portable_serialize_10_b8(coefficient);
    Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3613(&serialized,
        ((core_ops_range_Range_08){ (size_t)20U * i0, (size_t)20U * i0 + (size_t)20U })),
      Eurydice_array_to_slice_shared_c2(&bytes),
      uint8_t);
  }
  return serialized;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
- OUT_LEN= 320
*/
static KRML_MUSTINLINE Eurydice_arr_b70
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_fe(const Eurydice_arr_b9 *re)
{
  return libcrux_ml_kem_serialize_compress_then_serialize_10_ff(re);
}

/**
 Call [`compress_then_serialize_ring_element_u`] on each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.compress_then_serialize_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- OUT_LEN= 960
- COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_compress_then_serialize_u_43(
  Eurydice_arr_1d input,
  Eurydice_mut_borrow_slice_u8 out
)
{
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9 re = input.data[i0];
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        (
          (core_ops_range_Range_08){
            i0 * ((size_t)960U / (size_t)3U),
            (i0 + (size_t)1U) * ((size_t)960U / (size_t)3U)
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b70
    lvalue = libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_fe(&re);
    Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_d3(&lvalue), uint8_t);
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE tuple_ac
libcrux_ml_kem_ind_cpa_encrypt_c1_85(
  Eurydice_borrow_slice_u8 randomness,
  const Eurydice_arr_dd0 *matrix,
  Eurydice_mut_borrow_slice_u8 ciphertext
)
{
  Eurydice_arr_3e0 prf_input = libcrux_ml_kem_utils_into_padded_array_c8(randomness);
  Eurydice_arr_1d arr_struct0;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct0.data[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_85(&lvalue, i);
  }
  Eurydice_arr_1d r_as_ntt = arr_struct0;
  uint8_t
  domain_separator0 =
    libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_3b(&r_as_ntt,
      &prf_input,
      0U);
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_85(&lvalue, i);
  }
  Eurydice_arr_1d error_1 = arr_struct;
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_3b(&prf_input,
      domain_separator0,
      &error_1);
  prf_input.data[32U] = domain_separator;
  Eurydice_arr_d1
  prf_output =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_410(Eurydice_array_to_slice_shared_61(&prf_input));
  Eurydice_arr_b9
  error_2 =
    libcrux_ml_kem_sampling_sample_from_binomial_distribution_a0(Eurydice_array_to_slice_shared_18(&prf_output));
  Eurydice_arr_1d u = libcrux_ml_kem_matrix_compute_vector_u_1b(matrix, &r_as_ntt, &error_1);
  libcrux_ml_kem_ind_cpa_compress_then_serialize_u_43(u, ciphertext);
  return ((tuple_ac){ r_as_ntt, error_2 });
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_then_decompress_message_ea(
  const Eurydice_arr_600 *serialized
)
{
  Eurydice_arr_b9 re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < (size_t)16U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient_compressed =
      libcrux_ml_kem_vector_portable_deserialize_1_b8(Eurydice_array_to_subslice_shared_36(serialized,
          ((core_ops_range_Range_08){ (size_t)2U * i0, (size_t)2U * i0 + (size_t)2U })));
    Eurydice_arr_e2
    uu____0 = libcrux_ml_kem_vector_portable_decompress_1_b8(coefficient_compressed);
    re.data[i0] = uu____0;
  }
  return re;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_add_message_error_reduce_ea(
  const Eurydice_arr_b9 *myself,
  const Eurydice_arr_b9 *message,
  Eurydice_arr_b9 result
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient_normal_form =
      libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(result.data[i0],
        (int16_t)1441);
    Eurydice_arr_e2
    sum1 = libcrux_ml_kem_vector_portable_add_b8(myself->data[i0], &message->data[i0]);
    Eurydice_arr_e2 sum2 = libcrux_ml_kem_vector_portable_add_b8(coefficient_normal_form, &sum1);
    Eurydice_arr_e2 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(sum2);
    result.data[i0] = red;
  }
  return result;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_polynomial_add_message_error_reduce_d6_ea(
  const Eurydice_arr_b9 *self,
  const Eurydice_arr_b9 *message,
  Eurydice_arr_b9 result
)
{
  return libcrux_ml_kem_polynomial_add_message_error_reduce_ea(self, message, result);
}

/**
 Compute InverseNTT(tᵀ ◦ r̂) + e₂ + message
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_b9
libcrux_ml_kem_matrix_compute_ring_element_v_1b(
  const Eurydice_arr_1d *t_as_ntt,
  const Eurydice_arr_1d *r_as_ntt,
  const Eurydice_arr_b9 *error_2,
  const Eurydice_arr_b9 *message
)
{
  Eurydice_arr_b9 result = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9
    product =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&t_as_ntt->data[i0],
        &r_as_ntt->data[i0]);
    libcrux_ml_kem_polynomial_add_to_ring_element_d6_1b(&result, &product);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_1b(&result);
  return libcrux_ml_kem_polynomial_add_message_error_reduce_d6_ea(error_2, message, result);
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 4
*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_vector_portable_compress_compress_d1(Eurydice_arr_e2 a)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    size_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient((uint8_t)(int32_t)4,
          libcrux_secrets_int_as_u16_f5(a.data[i0])));
    a.data[i0] = uu____0;
  }
  return a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 4
*/
static inline Eurydice_arr_e2 libcrux_ml_kem_vector_portable_compress_b8_d1(Eurydice_arr_e2 a)
{
  return libcrux_ml_kem_vector_portable_compress_compress_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_serialize_compress_then_serialize_4_ea(
  Eurydice_arr_b9 re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient =
      libcrux_ml_kem_vector_portable_compress_b8_d1(libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re.data[i0]));
    Eurydice_array_u8x8 bytes = libcrux_ml_kem_vector_portable_serialize_4_b8(coefficient);
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_7e(serialized,
        ((core_ops_range_Range_08){ (size_t)8U * i0, (size_t)8U * i0 + (size_t)8U })),
      Eurydice_array_to_slice_shared_41(&bytes),
      uint8_t);
  }
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
- OUT_LEN= 128
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_6c(
  Eurydice_arr_b9 re,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_kem_serialize_compress_then_serialize_4_ea(re, out);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- V_COMPRESSION_FACTOR= 4
- C2_LEN= 128
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_encrypt_c2_6c(
  const Eurydice_arr_1d *t_as_ntt,
  const Eurydice_arr_1d *r_as_ntt,
  const Eurydice_arr_b9 *error_2,
  const Eurydice_arr_600 *message,
  Eurydice_mut_borrow_slice_u8 ciphertext
)
{
  Eurydice_arr_b9
  message_as_ring_element =
    libcrux_ml_kem_serialize_deserialize_then_decompress_message_ea(message);
  Eurydice_arr_b9
  v =
    libcrux_ml_kem_matrix_compute_ring_element_v_1b(t_as_ntt,
      r_as_ntt,
      error_2,
      &message_as_ring_element);
  libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_6c(v, ciphertext);
}

/**
 This function implements <strong>Algorithm 13</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE encryption algorithm.

 Algorithm 13 is reproduced below:

 ```plaintext
 Input: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
 Input: message m ∈ 𝔹^{32}.
 Input: encryption randomness r ∈ 𝔹^{32}.
 Output: ciphertext c ∈ 𝔹^{32(dᵤk + dᵥ)}.

 N ← 0
 t̂ ← ByteDecode₁₂(ekₚₖₑ[0:384k])
 ρ ← ekₚₖₑ[384k: 384k + 32]
 for (i ← 0; i < k; i++)
     for(j ← 0; j < k; j++)
         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
     end for
 end for
 for(i ← 0; i < k; i++)
     r[i] ← (SamplePolyCBD_){η₁}((PRF_){η₁}(r,N))
     N ← N + 1
 end for
 for(i ← 0; i < k; i++)
     e₁[i] ← (SamplePolyCBD_){η₂}((PRF_){η₂}(r,N))
     N ← N + 1
 end for
 e₂ ← (SamplePolyCBD_){η₂}((PRF_){η₂}(r,N))
 r̂ ← NTT(r)
 u ← NTT-¹(Âᵀ ◦ r̂) + e₁
 μ ← Decompress₁(ByteDecode₁(m)))
 v ← NTT-¹(t̂ᵀ ◦ rˆ) + e₂ + μ
 c₁ ← (ByteEncode_){dᵤ}((Compress_){dᵤ}(u))
 c₂ ← (ByteEncode_){dᵥ}((Compress_){dᵥ}(v))
 return c ← (c₁ ‖ c₂)
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_LEN= 960
- C2_LEN= 128
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE Eurydice_arr_2c
libcrux_ml_kem_ind_cpa_encrypt_unpacked_2a(
  const libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 *public_key,
  const Eurydice_arr_600 *message,
  Eurydice_borrow_slice_u8 randomness
)
{
  Eurydice_arr_2c ciphertext = { { 0U } };
  tuple_ac
  uu____0 =
    libcrux_ml_kem_ind_cpa_encrypt_c1_85(randomness,
      &public_key->A,
      Eurydice_array_to_subslice_mut_3614(&ciphertext,
        ((core_ops_range_Range_08){ (size_t)0U, (size_t)960U })));
  Eurydice_arr_1d r_as_ntt = uu____0.fst;
  Eurydice_arr_b9 error_2 = uu____0.snd;
  libcrux_ml_kem_ind_cpa_encrypt_c2_6c(&public_key->t_as_ntt,
    &r_as_ntt,
    &error_2,
    message,
    Eurydice_array_to_subslice_from_mut_8c3(&ciphertext, (size_t)960U));
  return ciphertext;
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_LEN= 960
- C2_LEN= 128
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE Eurydice_arr_2c
libcrux_ml_kem_ind_cpa_encrypt_2a(
  Eurydice_borrow_slice_u8 public_key,
  const Eurydice_arr_600 *message,
  Eurydice_borrow_slice_u8 randomness
)
{
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
  unpacked_public_key = libcrux_ml_kem_ind_cpa_build_unpacked_public_key_3f(public_key);
  return libcrux_ml_kem_ind_cpa_encrypt_unpacked_2a(&unpacked_public_key, message, randomness);
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.kdf_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_variant_kdf_39_d6(
  Eurydice_borrow_slice_u8 shared_secret,
  const Eurydice_arr_2c *_
)
{
  Eurydice_arr_600 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_6e(&out), shared_secret, uint8_t);
  return out;
}

/**
 This code verifies on some machines, runs out of memory on others
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.decapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_ind_cca_decapsulate_62(
  const Eurydice_arr_ea *private_key,
  const Eurydice_arr_2c *ciphertext
)
{
  Eurydice_borrow_slice_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_private_key_b4(Eurydice_array_to_slice_shared_ec(private_key));
  Eurydice_borrow_slice_u8 ind_cpa_secret_key = uu____0.fst;
  Eurydice_borrow_slice_u8 ind_cpa_public_key = uu____0.snd;
  Eurydice_borrow_slice_u8 ind_cpa_public_key_hash = uu____0.thd;
  Eurydice_borrow_slice_u8 implicit_rejection_value = uu____0.f3;
  Eurydice_arr_600 decrypted = libcrux_ml_kem_ind_cpa_decrypt_42(ind_cpa_secret_key, ciphertext);
  Eurydice_arr_060
  to_hash0 =
    libcrux_ml_kem_utils_into_padded_array_24(Eurydice_array_to_slice_shared_6e(&decrypted));
  Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_8c1(&to_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE),
    ind_cpa_public_key_hash,
    uint8_t);
  Eurydice_arr_060
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_e0(Eurydice_array_to_slice_shared_d8(&to_hash0));
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_d8(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret0 = uu____1.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_480 to_hash = libcrux_ml_kem_utils_into_padded_array_15(implicit_rejection_value);
  Eurydice_mut_borrow_slice_u8
  uu____2 =
    Eurydice_array_to_subslice_from_mut_8c2(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE);
  Eurydice_slice_copy(uu____2, libcrux_ml_kem_types_as_ref_d3_80(ciphertext), uint8_t);
  Eurydice_arr_600
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_41(Eurydice_array_to_slice_shared_74(&to_hash));
  Eurydice_arr_2c
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_2a(ind_cpa_public_key,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_slice_u8
  uu____3 = Eurydice_array_to_slice_shared_6e(&implicit_rejection_shared_secret);
  Eurydice_arr_600
  implicit_rejection_shared_secret0 =
    libcrux_ml_kem_variant_kdf_39_d6(uu____3,
      libcrux_ml_kem_types_as_slice_a9_80(ciphertext));
  Eurydice_arr_600
  shared_secret =
    libcrux_ml_kem_variant_kdf_39_d6(shared_secret0,
      libcrux_ml_kem_types_as_slice_a9_80(ciphertext));
  Eurydice_borrow_slice_u8 uu____4 = libcrux_ml_kem_types_as_ref_d3_80(ciphertext);
  return
    libcrux_ml_kem_constant_time_ops_compare_ciphertexts_select_shared_secret_in_constant_time(uu____4,
      Eurydice_array_to_slice_shared_42(&expected_ciphertext),
      Eurydice_array_to_slice_shared_6e(&shared_secret),
      Eurydice_array_to_slice_shared_6e(&implicit_rejection_shared_secret0));
}

/**
 Portable decapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.decapsulate
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
static inline Eurydice_arr_600
libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_35(
  const Eurydice_arr_ea *private_key,
  const Eurydice_arr_2c *ciphertext
)
{
  return libcrux_ml_kem_ind_cca_decapsulate_62(private_key, ciphertext);
}

/**
 Decapsulate ML-KEM 768

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
*/
static inline Eurydice_arr_600
libcrux_ml_kem_mlkem768_portable_decapsulate(
  const Eurydice_arr_ea *private_key,
  const Eurydice_arr_2c *ciphertext
)
{
  return libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_35(private_key, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.entropy_preprocess_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_variant_entropy_preprocess_39_9c(Eurydice_borrow_slice_u8 randomness)
{
  Eurydice_arr_600 out = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_6e(&out), randomness, uint8_t);
  return out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.H_4a
with const generics
- K= 3
*/
static inline Eurydice_arr_600
libcrux_ml_kem_hash_functions_portable_H_4a_e0(Eurydice_borrow_slice_u8 input)
{
  return libcrux_ml_kem_hash_functions_portable_H(input);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.encapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE tuple_38
libcrux_ml_kem_ind_cca_encapsulate_ca(
  const Eurydice_arr_74 *public_key,
  const Eurydice_arr_600 *randomness
)
{
  Eurydice_arr_600
  randomness0 =
    libcrux_ml_kem_variant_entropy_preprocess_39_9c(Eurydice_array_to_slice_shared_6e(randomness));
  Eurydice_arr_060
  to_hash =
    libcrux_ml_kem_utils_into_padded_array_24(Eurydice_array_to_slice_shared_6e(&randomness0));
  Eurydice_mut_borrow_slice_u8
  uu____0 =
    Eurydice_array_to_subslice_from_mut_8c1(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE);
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_600
  lvalue =
    libcrux_ml_kem_hash_functions_portable_H_4a_e0(Eurydice_array_to_slice_shared_45(libcrux_ml_kem_types_as_slice_e6_d0(public_key)));
  Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_6e(&lvalue), uint8_t);
  Eurydice_arr_060
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_e0(Eurydice_array_to_slice_shared_d8(&to_hash));
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_d8(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_2c
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_2a(Eurydice_array_to_slice_shared_45(libcrux_ml_kem_types_as_slice_e6_d0(public_key)),
      &randomness0,
      pseudorandomness);
  Eurydice_arr_2c uu____2 = libcrux_ml_kem_types_from_e0_80(ciphertext);
  return ((tuple_38){ uu____2, libcrux_ml_kem_variant_kdf_39_d6(shared_secret, &ciphertext) });
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.encapsulate
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static inline tuple_38
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_cd(
  const Eurydice_arr_74 *public_key,
  const Eurydice_arr_600 *randomness
)
{
  return libcrux_ml_kem_ind_cca_encapsulate_ca(public_key, randomness);
}

/**
 Encapsulate ML-KEM 768

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
 bytes of `randomness`.
*/
static inline tuple_38
libcrux_ml_kem_mlkem768_portable_encapsulate(
  const Eurydice_arr_74 *public_key,
  Eurydice_arr_600 randomness
)
{
  return libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_cd(public_key, &randomness);
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPrivateKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_70
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline Eurydice_arr_1d libcrux_ml_kem_ind_cpa_unpacked_default_70_1b(void)
{
  Eurydice_arr_1d lit;
  Eurydice_arr_b9 repeat_expression[3U];
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    repeat_expression[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  memcpy(lit.data, repeat_expression, (size_t)3U * sizeof (Eurydice_arr_b9));
  return lit;
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.cpa_keygen_seed_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_060
libcrux_ml_kem_variant_cpa_keygen_seed_39_9c(Eurydice_borrow_slice_u8 key_generation_seed)
{
  Eurydice_arr_3e0 seed = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3612(&seed,
      (
        (core_ops_range_Range_08){
          (size_t)0U,
          LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE
        }
      )),
    key_generation_seed,
    uint8_t);
  seed.data[LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE] = (uint8_t)(size_t)3U;
  return
    libcrux_ml_kem_hash_functions_portable_G_4a_e0(Eurydice_array_to_slice_shared_61(&seed));
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@3]> for libcrux_ml_kem::ind_cpa::generate_keypair_unpacked::closure<Vector, Hasher, Scheme, K, ETA1, ETA1_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3, TraitClause@4, TraitClause@5]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair_unpacked.call_mut_73
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_1c(void **_, size_t tupled_args)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.to_standard_domain
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_e2
libcrux_ml_kem_polynomial_to_standard_domain_ea(Eurydice_arr_e2 vector)
{
  return
    libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(vector,
      LIBCRUX_ML_KEM_VECTOR_TRAITS_MONTGOMERY_R_SQUARED_MOD_FIELD_MODULUS);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_add_standard_error_reduce_ea(
  Eurydice_arr_b9 *myself,
  const Eurydice_arr_b9 *error
)
{
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t j = i;
    Eurydice_arr_e2
    coefficient_normal_form = libcrux_ml_kem_polynomial_to_standard_domain_ea(myself->data[j]);
    Eurydice_arr_e2
    sum = libcrux_ml_kem_vector_portable_add_b8(coefficient_normal_form, &error->data[j]);
    Eurydice_arr_e2 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(sum);
    myself->data[j] = red;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE void
libcrux_ml_kem_polynomial_add_standard_error_reduce_d6_ea(
  Eurydice_arr_b9 *self,
  const Eurydice_arr_b9 *error
)
{
  libcrux_ml_kem_polynomial_add_standard_error_reduce_ea(self, error);
}

/**
 Compute Â ◦ ŝ + ê
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_As_plus_e
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_matrix_compute_As_plus_e_1b(
  Eurydice_arr_1d *t_as_ntt,
  const Eurydice_arr_dd0 *matrix_A,
  const Eurydice_arr_1d *s_as_ntt,
  const Eurydice_arr_1d *error_as_ntt
)
{
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    const Eurydice_arr_1d *row = &matrix_A->data[i0];
    Eurydice_arr_b9 uu____0 = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    t_as_ntt->data[i0] = uu____0;
    for (size_t i1 = (size_t)0U; i1 < (size_t)3U; i1++)
    {
      size_t j = i1;
      const Eurydice_arr_b9 *matrix_element = &row->data[j];
      Eurydice_arr_b9
      product = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(matrix_element, &s_as_ntt->data[j]);
      libcrux_ml_kem_polynomial_add_to_ring_element_d6_1b(&t_as_ntt->data[i0], &product);
    }
    libcrux_ml_kem_polynomial_add_standard_error_reduce_d6_ea(&t_as_ntt->data[i0],
      &error_as_ntt->data[i0]);
  }
}

/**
 This function implements most of <strong>Algorithm 12</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE key generation algorithm.

 We say "most of" since Algorithm 12 samples the required randomness within
 the function itself, whereas this implementation expects it to be provided
 through the `key_generation_seed` parameter.

 Algorithm 12 is reproduced below:

 ```plaintext
 Output: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
 Output: decryption key dkₚₖₑ ∈ 𝔹^{384k}.

 d ←$ B
 (ρ,σ) ← G(d)
 N ← 0
 for (i ← 0; i < k; i++)
     for(j ← 0; j < k; j++)
         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
     end for
 end for
 for(i ← 0; i < k; i++)
     s[i] ← (SamplePolyCBD_){η₁}((PRF_){η₁}(σ,N))
     N ← N + 1
 end for
 for(i ← 0; i < k; i++)
     e[i] ← (SamplePolyCBD_){η₂}((PRF_){η₂}(σ,N))
     N ← N + 1
 end for
 ŝ ← NTT(s)
 ê ← NTT(e)
 t̂ ← Â◦ŝ + ê
 ekₚₖₑ ← ByteEncode₁₂(t̂) ‖ ρ
 dkₚₖₑ ← ByteEncode₁₂(ŝ)
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_1c(
  Eurydice_borrow_slice_u8 key_generation_seed,
  Eurydice_arr_1d *private_key,
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 *public_key
)
{
  Eurydice_arr_060 hashed = libcrux_ml_kem_variant_cpa_keygen_seed_39_9c(key_generation_seed);
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_d8(&hashed),
      (size_t)32U,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_A = uu____0.fst;
  Eurydice_borrow_slice_u8 seed_for_secret_and_error = uu____0.snd;
  Eurydice_arr_dd0 *uu____1 = &public_key->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_48 lvalue0 = libcrux_ml_kem_utils_into_padded_array_b6(seed_for_A);
  libcrux_ml_kem_matrix_sample_matrix_A_2b(uu____1, &lvalue0, true);
  Eurydice_arr_3e0
  prf_input = libcrux_ml_kem_utils_into_padded_array_c8(seed_for_secret_and_error);
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_3b(private_key,
      &prf_input,
      0U);
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] =
      libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_1c(&lvalue,
        i);
  }
  Eurydice_arr_1d error_as_ntt = arr_struct;
  libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_3b(&error_as_ntt,
    &prf_input,
    domain_separator);
  libcrux_ml_kem_matrix_compute_As_plus_e_1b(&public_key->t_as_ntt,
    &public_key->A,
    &private_key[0U],
    &error_as_ntt);
  Eurydice_arr_600 arr;
  memcpy(arr.data, seed_for_A.ptr, (size_t)32U * sizeof (uint8_t));
  Eurydice_arr_600 uu____2 = unwrap_26_07((Result_fd){ .tag = Ok, .val = { .case_Ok = arr } });
  public_key->seed_for_A = uu____2;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.serialize_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static KRML_MUSTINLINE Eurydice_arr_cc
libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(const Eurydice_arr_b9 *re)
{
  Eurydice_arr_cc serialized = { { 0U } };
  for (size_t i = (size_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    size_t i0 = i;
    Eurydice_arr_e2
    coefficient = libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re->data[i0]);
    Eurydice_arr_6d bytes = libcrux_ml_kem_vector_portable_serialize_12_b8(coefficient);
    Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3615(&serialized,
        ((core_ops_range_Range_08){ (size_t)24U * i0, (size_t)24U * i0 + (size_t)24U })),
      Eurydice_array_to_slice_shared_0b(&bytes),
      uint8_t);
  }
  return serialized;
}

/**
 Call [`serialize_uncompressed_ring_element`] for each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_vector
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_serialize_vector_1b(
  const Eurydice_arr_1d *key,
  Eurydice_mut_borrow_slice_u8 out
)
{
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    size_t i0 = i;
    Eurydice_arr_b9 re = key->data[i0];
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_7e(out,
        (
          (core_ops_range_Range_08){
            i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT,
            (i0 + (size_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_cc lvalue = libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(&re);
    Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_fe(&lvalue), uint8_t);
  }
}

/**
 Concatenate `t` and `ρ` into the public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_public_key_mut
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cpa_serialize_public_key_mut_89(
  const Eurydice_arr_1d *t_as_ntt,
  Eurydice_borrow_slice_u8 seed_for_a,
  Eurydice_arr_74 *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_vector_1b(t_as_ntt,
    Eurydice_array_to_subslice_mut_3616(serialized,
      (
        (core_ops_range_Range_08){
          (size_t)0U,
          libcrux_ml_kem_constants_ranked_bytes_per_ring_element((size_t)3U)
        }
      )));
  Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_8c4(serialized,
      libcrux_ml_kem_constants_ranked_bytes_per_ring_element((size_t)3U)),
    seed_for_a,
    uint8_t);
}

/**
 Concatenate `t` and `ρ` into the public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE Eurydice_arr_74
libcrux_ml_kem_ind_cpa_serialize_public_key_89(
  const Eurydice_arr_1d *t_as_ntt,
  Eurydice_borrow_slice_u8 seed_for_a
)
{
  Eurydice_arr_74 public_key_serialized = { { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_public_key_mut_89(t_as_ntt,
    seed_for_a,
    &public_key_serialized);
  return public_key_serialized;
}

/**
 Serialize the secret key from the unpacked key pair generation.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_unpacked_secret_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PRIVATE_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
static inline tuple_f4
libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_key_6c(
  const libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 *public_key,
  const Eurydice_arr_1d *private_key
)
{
  Eurydice_arr_74
  public_key_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_key_89(&public_key->t_as_ntt,
      Eurydice_array_to_slice_shared_6e(&public_key->seed_for_A));
  Eurydice_arr_60 secret_key_serialized = { { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_vector_1b(private_key,
    Eurydice_array_to_slice_mut_06(&secret_key_serialized));
  return ((tuple_f4){ secret_key_serialized, public_key_serialized });
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- PRIVATE_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cpa_generate_keypair_ea(Eurydice_borrow_slice_u8 key_generation_seed)
{
  Eurydice_arr_1d private_key = libcrux_ml_kem_ind_cpa_unpacked_default_70_1b();
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
  public_key = libcrux_ml_kem_ind_cpa_unpacked_default_8b_1b();
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_1c(key_generation_seed,
    &private_key,
    &public_key);
  return libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_key_6c(&public_key, &private_key);
}

/**
 Serialize the secret key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key_mut
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_serialize_kem_secret_key_mut_d6(
  Eurydice_borrow_slice_u8 private_key,
  Eurydice_borrow_slice_u8 public_key,
  Eurydice_borrow_slice_u8 implicit_rejection_value,
  Eurydice_arr_ea *serialized
)
{
  size_t pointer = (size_t)0U;
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3617(serialized,
      ((core_ops_range_Range_08){ pointer, pointer + private_key.meta })),
    private_key,
    uint8_t);
  pointer = pointer + private_key.meta;
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3617(serialized,
      ((core_ops_range_Range_08){ pointer, pointer + public_key.meta })),
    public_key,
    uint8_t);
  pointer = pointer + public_key.meta;
  Eurydice_mut_borrow_slice_u8
  uu____0 =
    Eurydice_array_to_subslice_mut_3617(serialized,
      ((core_ops_range_Range_08){ pointer, pointer + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE }));
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_600 lvalue = libcrux_ml_kem_hash_functions_portable_H_4a_e0(public_key);
  Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_6e(&lvalue), uint8_t);
  pointer = pointer + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE;
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_3617(serialized,
      ((core_ops_range_Range_08){ pointer, pointer + implicit_rejection_value.meta })),
    implicit_rejection_value,
    uint8_t);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
static KRML_MUSTINLINE Eurydice_arr_ea
libcrux_ml_kem_ind_cca_serialize_kem_secret_key_d6(
  Eurydice_borrow_slice_u8 private_key,
  Eurydice_borrow_slice_u8 public_key,
  Eurydice_borrow_slice_u8 implicit_rejection_value
)
{
  Eurydice_arr_ea out = { { 0U } };
  libcrux_ml_kem_ind_cca_serialize_kem_secret_key_mut_d6(private_key,
    public_key,
    implicit_rejection_value,
    &out);
  return out;
}

/**
 Packed API

 Generate a key pair.

 Depending on the `Vector` and `Hasher` used, this requires different hardware
 features
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE libcrux_ml_kem_mlkem768_MlKem768KeyPair
libcrux_ml_kem_ind_cca_generate_keypair_15(const Eurydice_arr_060 *randomness)
{
  Eurydice_borrow_slice_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_to_subslice_shared_367(randomness,
      (
        (core_ops_range_Range_08){
          (size_t)0U,
          LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE
        }
      ));
  Eurydice_borrow_slice_u8
  implicit_rejection_value =
    Eurydice_array_to_subslice_from_shared_8c1(randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE);
  tuple_f4 uu____0 = libcrux_ml_kem_ind_cpa_generate_keypair_ea(ind_cpa_keypair_randomness);
  Eurydice_arr_60 ind_cpa_private_key = uu____0.fst;
  Eurydice_arr_74 public_key = uu____0.snd;
  Eurydice_arr_ea
  secret_key_serialized =
    libcrux_ml_kem_ind_cca_serialize_kem_secret_key_d6(Eurydice_array_to_slice_shared_06(&ind_cpa_private_key),
      Eurydice_array_to_slice_shared_45(&public_key),
      implicit_rejection_value);
  Eurydice_arr_ea private_key = libcrux_ml_kem_types_from_77_28(secret_key_serialized);
  return
    libcrux_ml_kem_types_from_17_74(private_key,
      libcrux_ml_kem_types_from_fd_d0(public_key));
}

/**
 Portable generate key pair.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.generate_keypair
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static inline libcrux_ml_kem_mlkem768_MlKem768KeyPair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_ce(
  const Eurydice_arr_060 *randomness
)
{
  return libcrux_ml_kem_ind_cca_generate_keypair_15(randomness);
}

/**
 Generate ML-KEM 768 Key Pair
*/
static inline libcrux_ml_kem_mlkem768_MlKem768KeyPair
libcrux_ml_kem_mlkem768_portable_generate_key_pair(Eurydice_arr_060 randomness)
{
  return libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_ce(&randomness);
}

/**
 Validate an ML-KEM private key.

 This implements the Hash check in 7.3 3.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_private_key_only
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_private_key_only_d6(const Eurydice_arr_ea *private_key)
{
  Eurydice_arr_600
  t =
    libcrux_ml_kem_hash_functions_portable_H_4a_e0(Eurydice_array_to_subslice_shared_368(private_key,
        (
          (core_ops_range_Range_08){
            (size_t)384U * (size_t)3U,
            (size_t)768U * (size_t)3U + (size_t)32U
          }
        )));
  Eurydice_borrow_slice_u8
  expected =
    Eurydice_array_to_subslice_shared_368(private_key,
      (
        (core_ops_range_Range_08){
          (size_t)768U * (size_t)3U + (size_t)32U,
          (size_t)768U * (size_t)3U + (size_t)64U
        }
      ));
  return Eurydice_array_eq_slice_shared((size_t)32U, &t, &expected, uint8_t, bool);
}

/**
 Validate an ML-KEM private key.

 This implements the Hash check in 7.3 3.
 Note that the size checks in 7.2 1 and 2 are covered by the `SECRET_KEY_SIZE`
 and `CIPHERTEXT_SIZE` in the `private_key` and `ciphertext` types.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_private_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CIPHERTEXT_SIZE= 1088
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_private_key_37(
  const Eurydice_arr_ea *private_key,
  const Eurydice_arr_2c *_ciphertext
)
{
  return libcrux_ml_kem_ind_cca_validate_private_key_only_d6(private_key);
}

/**
 Private key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_private_key
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CIPHERTEXT_SIZE= 1088
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_key_31(
  const Eurydice_arr_ea *private_key,
  const Eurydice_arr_2c *ciphertext
)
{
  return libcrux_ml_kem_ind_cca_validate_private_key_37(private_key, ciphertext);
}

/**
 Validate a private key.

 Returns `true` if valid, and `false` otherwise.
*/
static inline bool
libcrux_ml_kem_mlkem768_portable_validate_private_key(
  const Eurydice_arr_ea *private_key,
  const Eurydice_arr_2c *ciphertext
)
{
  return
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_key_31(private_key,
      ciphertext);
}

/**
 Private key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_private_key_only
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_key_only_41(
  const Eurydice_arr_ea *private_key
)
{
  return libcrux_ml_kem_ind_cca_validate_private_key_only_d6(private_key);
}

/**
 Validate the private key only.

 Returns `true` if valid, and `false` otherwise.
*/
static inline bool
libcrux_ml_kem_mlkem768_portable_validate_private_key_only(const Eurydice_arr_ea *private_key)
{
  return
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_key_only_41(private_key);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::serialize::deserialize_ring_elements_reduced_out::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced_out.call_mut_0b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_call_mut_0b_1b(
  void **_,
  size_t tupled_args
)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
 This function deserializes ring elements and reduces the result by the field
 modulus.

 This function MUST NOT be used on secret inputs.
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced_out
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE Eurydice_arr_1d
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_1b(
  Eurydice_borrow_slice_u8 public_key
)
{
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] =
      libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_call_mut_0b_1b(&lvalue,
        i);
  }
  Eurydice_arr_1d deserialized_pk = arr_struct;
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_1b(public_key, &deserialized_pk);
  return deserialized_pk;
}

/**
 Validate an ML-KEM public key.

 This implements the Modulus check in 7.2 2.
 Note that the size check in 7.2 1 is covered by the `PUBLIC_KEY_SIZE` in the
 `public_key` type.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_public_key_89(const Eurydice_arr_74 *public_key)
{
  Eurydice_arr_1d
  deserialized_pk =
    libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_1b(Eurydice_array_to_subslice_to_shared_6e0(public_key,
        libcrux_ml_kem_constants_ranked_bytes_per_ring_element((size_t)3U)));
  Eurydice_arr_74
  public_key_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_key_89(&deserialized_pk,
      Eurydice_array_to_subslice_from_shared_8c2(public_key,
        libcrux_ml_kem_constants_ranked_bytes_per_ring_element((size_t)3U)));
  return Eurydice_array_eq((size_t)1184U, public_key, &public_key_serialized, uint8_t);
}

/**
 Public key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_public_key
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_key_41(
  const Eurydice_arr_74 *public_key
)
{
  return libcrux_ml_kem_ind_cca_validate_public_key_89(public_key);
}

/**
 Validate a public key.

 Returns `true` if valid, and `false` otherwise.
*/
static inline bool
libcrux_ml_kem_mlkem768_portable_validate_public_key(const Eurydice_arr_74 *public_key)
{
  return libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_key_41(public_key);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
typedef struct libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0_s
{
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 ind_cpa_public_key;
  Eurydice_arr_600 public_key_hash;
}
libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0;

typedef libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0
libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPrivateKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
typedef struct libcrux_ml_kem_ind_cca_unpacked_MlKemPrivateKeyUnpacked_a0_s
{
  Eurydice_arr_1d ind_cpa_private_key;
  Eurydice_arr_600 implicit_rejection_value;
}
libcrux_ml_kem_ind_cca_unpacked_MlKemPrivateKeyUnpacked_a0;

typedef struct libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked_s
{
  libcrux_ml_kem_ind_cca_unpacked_MlKemPrivateKeyUnpacked_a0 private_key;
  libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 public_key;
}
libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.decapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_ind_cca_unpacked_decapsulate_51(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair,
  const Eurydice_arr_2c *ciphertext
)
{
  Eurydice_arr_600
  decrypted =
    libcrux_ml_kem_ind_cpa_decrypt_unpacked_42(&key_pair->private_key.ind_cpa_private_key,
      ciphertext);
  Eurydice_arr_060
  to_hash0 =
    libcrux_ml_kem_utils_into_padded_array_24(Eurydice_array_to_slice_shared_6e(&decrypted));
  Eurydice_mut_borrow_slice_u8
  uu____0 =
    Eurydice_array_to_subslice_from_mut_8c1(&to_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE);
  Eurydice_slice_copy(uu____0,
    Eurydice_array_to_slice_shared_6e(&key_pair->public_key.public_key_hash),
    uint8_t);
  Eurydice_arr_060
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_e0(Eurydice_array_to_slice_shared_d8(&to_hash0));
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_d8(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_480
  to_hash =
    libcrux_ml_kem_utils_into_padded_array_15(Eurydice_array_to_slice_shared_6e(&key_pair->private_key.implicit_rejection_value));
  Eurydice_mut_borrow_slice_u8
  uu____2 =
    Eurydice_array_to_subslice_from_mut_8c2(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE);
  Eurydice_slice_copy(uu____2, libcrux_ml_kem_types_as_ref_d3_80(ciphertext), uint8_t);
  Eurydice_arr_600
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_41(Eurydice_array_to_slice_shared_74(&to_hash));
  Eurydice_arr_2c
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_2a(&key_pair->public_key.ind_cpa_public_key,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_slice_u8 uu____3 = libcrux_ml_kem_types_as_ref_d3_80(ciphertext);
  uint8_t
  selector =
    libcrux_ml_kem_constant_time_ops_compare_ciphertexts_in_constant_time(uu____3,
      Eurydice_array_to_slice_shared_42(&expected_ciphertext));
  return
    libcrux_ml_kem_constant_time_ops_select_shared_secret_in_constant_time(shared_secret,
      Eurydice_array_to_slice_shared_6e(&implicit_rejection_shared_secret),
      selector);
}

/**
 Unpacked decapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.decapsulate
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
static KRML_MUSTINLINE Eurydice_arr_600
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_35(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair,
  const Eurydice_arr_2c *ciphertext
)
{
  return libcrux_ml_kem_ind_cca_unpacked_decapsulate_51(key_pair, ciphertext);
}

/**
 Decapsulate ML-KEM 768 (unpacked)

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an unpacked key pair of type [`MlKem768KeyPairUnpacked`]
 and an [`MlKem768Ciphertext`].
*/
static inline Eurydice_arr_600
libcrux_ml_kem_mlkem768_portable_unpacked_decapsulate(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *private_key,
  const Eurydice_arr_2c *ciphertext
)
{
  return
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_35(private_key,
      ciphertext);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encaps_prepare
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
static inline Eurydice_arr_060
libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_9c(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_borrow_slice_u8 pk_hash
)
{
  Eurydice_arr_060 to_hash = libcrux_ml_kem_utils_into_padded_array_24(randomness);
  Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_8c1(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_SIZE),
    pk_hash,
    uint8_t);
  return
    libcrux_ml_kem_hash_functions_portable_G_4a_e0(Eurydice_array_to_slice_shared_d8(&to_hash));
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- VECTOR_U_BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE tuple_38
libcrux_ml_kem_ind_cca_unpacked_encapsulate_0c(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *public_key,
  const Eurydice_arr_600 *randomness
)
{
  Eurydice_arr_060
  hashed =
    libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_9c(Eurydice_array_to_slice_shared_6e(randomness),
      Eurydice_array_to_slice_shared_6e(&public_key->public_key_hash));
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_d8(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret = uu____0.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____0.snd;
  Eurydice_arr_2c
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_2a(&public_key->ind_cpa_public_key,
      randomness,
      pseudorandomness);
  Eurydice_arr_600 shared_secret_array = { { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_6e(&shared_secret_array),
    shared_secret,
    uint8_t);
  return ((tuple_38){ libcrux_ml_kem_types_from_e0_80(ciphertext), shared_secret_array });
}

/**
 Unpacked encapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.encapsulate
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- VECTOR_U_BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE tuple_38
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_cd(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *public_key,
  const Eurydice_arr_600 *randomness
)
{
  return libcrux_ml_kem_ind_cca_unpacked_encapsulate_0c(public_key, randomness);
}

/**
 Encapsulate ML-KEM 768 (unpacked)

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an unpacked public key of type [`MlKem768PublicKeyUnpacked`],
 the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
*/
static inline tuple_38
libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *public_key,
  Eurydice_arr_600 randomness
)
{
  return
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_cd(public_key,
      &randomness);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cca::unpacked::transpose_a::closure::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a.closure.call_mut_b4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline Eurydice_arr_b9
libcrux_ml_kem_ind_cca_unpacked_transpose_a_closure_call_mut_b4_1b(
  void **_,
  size_t tupled_args
)
{
  return libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
This function found in impl {core::ops::function::FnMut<(usize), @Array<libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1], K>> for libcrux_ml_kem::ind_cca::unpacked::transpose_a::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a.call_mut_7b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline Eurydice_arr_1d
libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_7b_1b(void **_, size_t tupled_args)
{
  Eurydice_arr_1d arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] =
      libcrux_ml_kem_ind_cca_unpacked_transpose_a_closure_call_mut_b4_1b(&lvalue,
        i);
  }
  return arr_struct;
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.clone_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
static inline Eurydice_arr_b9
libcrux_ml_kem_polynomial_clone_c1_ea(const Eurydice_arr_b9 *self)
{
  return
    core_array__core__clone__Clone_for__Array_T__N___clone((size_t)16U,
      self,
      Eurydice_arr_e2,
      Eurydice_arr_b9);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline Eurydice_arr_dd0
libcrux_ml_kem_ind_cca_unpacked_transpose_a_1b(Eurydice_arr_dd0 ind_cpa_a)
{
  Eurydice_arr_dd0 arr_struct;
  for (size_t i = (size_t)0U; i < (size_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    void *lvalue = (void *)0U;
    arr_struct.data[i] = libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_7b_1b(&lvalue, i);
  }
  Eurydice_arr_dd0 A = arr_struct;
  for (size_t i0 = (size_t)0U; i0 < (size_t)3U; i0++)
  {
    size_t i1 = i0;
    for (size_t i = (size_t)0U; i < (size_t)3U; i++)
    {
      size_t j = i;
      Eurydice_arr_b9 uu____0 = libcrux_ml_kem_polynomial_clone_c1_ea(&ind_cpa_a.data[j].data[i1]);
      A.data[i1].data[j] = uu____0;
    }
  }
  return A;
}

/**
 Generate Unpacked Keys
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_unpacked_generate_keypair_15(
  Eurydice_arr_060 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *out
)
{
  Eurydice_borrow_slice_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_to_subslice_shared_367(&randomness,
      (
        (core_ops_range_Range_08){
          (size_t)0U,
          LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE
        }
      ));
  Eurydice_borrow_slice_u8
  implicit_rejection_value =
    Eurydice_array_to_subslice_from_shared_8c1(&randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_KEY_GENERATION_SEED_SIZE);
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_1c(ind_cpa_keypair_randomness,
    &out->private_key.ind_cpa_private_key,
    &out->public_key.ind_cpa_public_key);
  Eurydice_arr_dd0
  A = libcrux_ml_kem_ind_cca_unpacked_transpose_a_1b(out->public_key.ind_cpa_public_key.A);
  out->public_key.ind_cpa_public_key.A = A;
  Eurydice_arr_74
  pk_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_key_89(&out->public_key.ind_cpa_public_key.t_as_ntt,
      Eurydice_array_to_slice_shared_6e(&out->public_key.ind_cpa_public_key.seed_for_A));
  Eurydice_arr_600
  uu____0 =
    libcrux_ml_kem_hash_functions_portable_H_4a_e0(Eurydice_array_to_slice_shared_45(&pk_serialized));
  out->public_key.public_key_hash = uu____0;
  Eurydice_arr_600 arr;
  memcpy(arr.data, implicit_rejection_value.ptr, (size_t)32U * sizeof (uint8_t));
  Eurydice_arr_600 uu____1 = unwrap_26_07((Result_fd){ .tag = Ok, .val = { .case_Ok = arr } });
  out->private_key.implicit_rejection_value = uu____1;
}

/**
 Generate a key pair
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.generate_keypair
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_ce(
  Eurydice_arr_060 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *out
)
{
  libcrux_ml_kem_ind_cca_unpacked_generate_keypair_15(randomness, out);
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair_mut(
  Eurydice_arr_060 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_ce(randomness,
    key_pair);
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.default_30
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0
libcrux_ml_kem_ind_cca_unpacked_default_30_1b(void)
{
  return
    (
      (libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0){
        libcrux_ml_kem_ind_cpa_unpacked_default_8b_1b(),
        { { 0U } }
      }
    );
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.default_7b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked
libcrux_ml_kem_ind_cca_unpacked_default_7b_1b(void)
{
  libcrux_ml_kem_ind_cca_unpacked_MlKemPrivateKeyUnpacked_a0
  uu____0 = { libcrux_ml_kem_ind_cpa_unpacked_default_70_1b(), { { 0U } } };
  return
    (
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked){
        uu____0,
        libcrux_ml_kem_ind_cca_unpacked_default_30_1b()
      }
    );
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
static inline libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked
libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair(Eurydice_arr_060 randomness)
{
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked
  key_pair = libcrux_ml_kem_ind_cca_unpacked_default_7b_1b();
  libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair_mut(randomness, &key_pair);
  return key_pair;
}

/**
 Create a new, empty unpacked key.
*/
static inline libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked
libcrux_ml_kem_mlkem768_portable_unpacked_init_key_pair(void)
{
  return libcrux_ml_kem_ind_cca_unpacked_default_7b_1b();
}

/**
 Create a new, empty unpacked public key.
*/
static inline libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0
libcrux_ml_kem_mlkem768_portable_unpacked_init_public_key(void)
{
  return libcrux_ml_kem_ind_cca_unpacked_default_30_1b();
}

/**
 Take a serialized private key and generate an unpacked key pair from it.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.keys_from_private_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_unpacked_keys_from_private_key_42(
  const Eurydice_arr_ea *private_key,
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair
)
{
  Eurydice_borrow_slice_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_private_key_b4(Eurydice_array_to_slice_shared_ec(private_key));
  Eurydice_borrow_slice_u8 ind_cpa_secret_key = uu____0.fst;
  Eurydice_borrow_slice_u8 ind_cpa_public_key = uu____0.snd;
  Eurydice_borrow_slice_u8 ind_cpa_public_key_hash = uu____0.thd;
  Eurydice_borrow_slice_u8 implicit_rejection_value = uu____0.f3;
  libcrux_ml_kem_ind_cpa_deserialize_vector_1b(ind_cpa_secret_key,
    &key_pair->private_key.ind_cpa_private_key);
  libcrux_ml_kem_ind_cpa_build_unpacked_public_key_mut_3f(ind_cpa_public_key,
    &key_pair->public_key.ind_cpa_public_key);
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_6e(&key_pair->public_key.public_key_hash),
    ind_cpa_public_key_hash,
    uint8_t);
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_6e(&key_pair->private_key.implicit_rejection_value),
    implicit_rejection_value,
    uint8_t);
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_6e(&key_pair->public_key.ind_cpa_public_key.seed_for_A),
    Eurydice_slice_subslice_from_shared_6b(ind_cpa_public_key, (size_t)1152U),
    uint8_t);
}

/**
 Take a serialized private key and generate an unpacked key pair from it.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.keypair_from_private_key
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_private_key_fd(
  const Eurydice_arr_ea *private_key,
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair
)
{
  libcrux_ml_kem_ind_cca_unpacked_keys_from_private_key_42(private_key, key_pair);
}

/**
 Get an unpacked key from a private key.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_from_private_mut(
  const Eurydice_arr_ea *private_key,
  libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_private_key_fd(private_key,
    key_pair);
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_private_key_mut_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_unpacked_serialized_private_key_mut_11_43(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *self,
  Eurydice_arr_ea *serialized
)
{
  tuple_f4
  uu____0 =
    libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_key_6c(&self->public_key.ind_cpa_public_key,
      &self->private_key.ind_cpa_private_key);
  Eurydice_arr_60 ind_cpa_private_key = uu____0.fst;
  Eurydice_arr_74 ind_cpa_public_key = uu____0.snd;
  libcrux_ml_kem_ind_cca_serialize_kem_secret_key_mut_d6(Eurydice_array_to_slice_shared_06(&ind_cpa_private_key),
    Eurydice_array_to_slice_shared_45(&ind_cpa_public_key),
    Eurydice_array_to_slice_shared_6e(&self->private_key.implicit_rejection_value),
    serialized);
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_private_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE Eurydice_arr_ea
libcrux_ml_kem_ind_cca_unpacked_serialized_private_key_11_43(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *self
)
{
  Eurydice_arr_ea sk = libcrux_ml_kem_types_default_d3_28();
  libcrux_ml_kem_ind_cca_unpacked_serialized_private_key_mut_11_43(self, &sk);
  return sk;
}

/**
 Get the serialized private key.
*/
static inline Eurydice_arr_ea
libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_private_key(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair
)
{
  return libcrux_ml_kem_ind_cca_unpacked_serialized_private_key_11_43(key_pair);
}

/**
 Get the serialized private key.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_private_key_mut(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair,
  Eurydice_arr_ea *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_private_key_mut_11_43(key_pair, serialized);
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE Eurydice_arr_74
libcrux_ml_kem_ind_cca_unpacked_serialized_dd_89(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *self
)
{
  return
    libcrux_ml_kem_types_from_fd_d0(libcrux_ml_kem_ind_cpa_serialize_public_key_89(&self->ind_cpa_public_key.t_as_ntt,
        Eurydice_array_to_slice_shared_6e(&self->ind_cpa_public_key.seed_for_A)));
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_public_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE Eurydice_arr_74
libcrux_ml_kem_ind_cca_unpacked_serialized_public_key_11_89(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *self
)
{
  return libcrux_ml_kem_ind_cca_unpacked_serialized_dd_89(&self->public_key);
}

/**
 Get the serialized public key.
*/
static inline Eurydice_arr_74
libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_public_key(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair
)
{
  return libcrux_ml_kem_ind_cca_unpacked_serialized_public_key_11_89(key_pair);
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_mut_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_89(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *self,
  Eurydice_arr_74 *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_public_key_mut_89(&self->ind_cpa_public_key.t_as_ntt,
    Eurydice_array_to_slice_shared_6e(&self->ind_cpa_public_key.seed_for_A),
    serialized);
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_public_key_mut_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_unpacked_serialized_public_key_mut_11_89(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *self,
  Eurydice_arr_74 *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_89(&self->public_key, serialized);
}

/**
 Get the serialized public key.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_public_key_mut(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair,
  Eurydice_arr_74 *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_public_key_mut_11_89(key_pair, serialized);
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.clone_91
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
libcrux_ml_kem_ind_cpa_unpacked_clone_91_1b(
  const libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0 *self
)
{
  Eurydice_arr_1d
  uu____0 =
    core_array__core__clone__Clone_for__Array_T__N___clone((size_t)3U,
      &self->t_as_ntt,
      Eurydice_arr_b9,
      Eurydice_arr_1d);
  Eurydice_arr_600
  uu____1 =
    core_array__core__clone__Clone_for__Array_T__N___clone((size_t)32U,
      &self->seed_for_A,
      uint8_t,
      Eurydice_arr_600);
  return
    (
      (libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0){
        uu____0,
        uu____1,
        core_array__core__clone__Clone_for__Array_T__N___clone((size_t)3U,
          &self->A,
          Eurydice_arr_1d,
          Eurydice_arr_dd0)
      }
    );
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.clone_d7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static inline libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0
libcrux_ml_kem_ind_cca_unpacked_clone_d7_1b(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *self
)
{
  libcrux_ml_kem_ind_cpa_unpacked_IndCpaPublicKeyUnpacked_a0
  uu____0 = libcrux_ml_kem_ind_cpa_unpacked_clone_91_1b(&self->ind_cpa_public_key);
  return
    (
      (libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0){
        uu____0,
        core_array__core__clone__Clone_for__Array_T__N___clone((size_t)32U,
          &self->public_key_hash,
          uint8_t,
          Eurydice_arr_600)
      }
    );
}

/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.public_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
static KRML_MUSTINLINE const
libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0
*libcrux_ml_kem_ind_cca_unpacked_public_key_11_1b(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *self
)
{
  return &self->public_key;
}

/**
 Get the unpacked public key.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_public_key(
  const libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *key_pair,
  libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *pk
)
{
  libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0
  uu____0 =
    libcrux_ml_kem_ind_cca_unpacked_clone_d7_1b(libcrux_ml_kem_ind_cca_unpacked_public_key_11_1b(key_pair));
  pk[0U] = uu____0;
}

/**
 Get the serialized public key.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_key(
  const libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *public_key,
  Eurydice_arr_74 *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_89(public_key, serialized);
}

/**
 Generate an unpacked key from a serialized key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.unpack_public_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_unpacked_unpack_public_key_0a(
  const Eurydice_arr_74 *public_key,
  libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *unpacked_public_key
)
{
  Eurydice_borrow_slice_u8
  uu____0 = Eurydice_array_to_subslice_to_shared_6e0(public_key, (size_t)1152U);
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_1b(uu____0,
    &unpacked_public_key->ind_cpa_public_key.t_as_ntt);
  unpacked_public_key->ind_cpa_public_key.seed_for_A =
    libcrux_ml_kem_utils_into_padded_array_9e(Eurydice_array_to_subslice_from_shared_8c2(public_key,
        (size_t)1152U));
  Eurydice_arr_dd0 *uu____2 = &unpacked_public_key->ind_cpa_public_key.A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_48
  lvalue =
    libcrux_ml_kem_utils_into_padded_array_b6(Eurydice_array_to_subslice_from_shared_8c2(public_key,
        (size_t)1152U));
  libcrux_ml_kem_matrix_sample_matrix_A_2b(uu____2, &lvalue, false);
  Eurydice_arr_600
  uu____3 =
    libcrux_ml_kem_hash_functions_portable_H_4a_e0(Eurydice_array_to_slice_shared_45(libcrux_ml_kem_types_as_slice_e6_d0(public_key)));
  unpacked_public_key->public_key_hash = uu____3;
}

/**
 Get the unpacked public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.unpack_public_key
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE void
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_public_key_31(
  const Eurydice_arr_74 *public_key,
  libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *unpacked_public_key
)
{
  libcrux_ml_kem_ind_cca_unpacked_unpack_public_key_0a(public_key, unpacked_public_key);
}

/**
 Get the unpacked public key.
*/
static inline void
libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_public_key(
  const Eurydice_arr_74 *public_key,
  libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0 *unpacked_public_key
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_public_key_31(public_key,
    unpacked_public_key);
}


#define libcrux_mlkem768_portable_H_DEFINED
#endif /* libcrux_mlkem768_portable_H */


/* rename some types to be a bit more ergonomic */
typedef Eurydice_arr_060 libcrux_mlkem768_keypair_rnd;
typedef Eurydice_arr_600 libcrux_mlkem768_enc_rnd;
#define libcrux_mlkem768_keypair libcrux_ml_kem_mlkem768_MlKem768KeyPair
#define libcrux_mlkem768_pk Eurydice_arr_74
#define libcrux_mlkem768_sk Eurydice_arr_ea
#define libcrux_mlkem768_ciphertext Eurydice_arr_2c
#define libcrux_mlkem768_enc_result tuple_38
#define libcrux_mlkem768_dec_result Eurydice_arr_600
