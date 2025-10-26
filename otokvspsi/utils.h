#pragma once
#include <cstddef>
#include <cstdint>
#include <unordered_set>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"
#include "yacl/crypto/hash/blake3.h"

struct U128Hasher {
  size_t operator()(const uint128_t& val) const {
    return static_cast<size_t>(val >> 64) ^ static_cast<size_t>(val);
  }
};

inline void aes128_encrypt_batch(uint128_t& a_out, const uint128_t keys[128],
                                 const uint128_t& y) {
  __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));

  uint8_t result_bytes[16] = {0};

  for (size_t i = 0; i < 128; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);

    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    alignas(16) uint8_t cipher[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipher), state);
    int bit = cipher[15] & 1;
    result_bytes[i >> 3] |= (bit << (i % 8));
  }
  std::memcpy(&a_out, result_bytes, 16);
}

inline void sha256_encrypt_batch(uint128_t& a_out, const uint128_t keys[128],
                                 const uint128_t& y) {
    __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));
      uint8_t result_bytes[16] = {0};

  for (size_t i = 0; i < 128; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);
    __m128i x = _mm_xor_si128(y_block, key_block);
    alignas(16) uint32_t wtmp[4];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(wtmp), x);
    uint32_t W0 = wtmp[0];
    uint32_t W1 = wtmp[1];
    __m128i abcd = _mm_set_epi32(0xa54ff53aU, 0x3c6ef372U, 0xbb67ae85U, 0x6a09e667U);
    __m128i efgh = _mm_set_epi32(0x5be0cd19U, 0x1f83d9abU, 0x9b05688cU, 0x510e527fU);

    const uint32_t K0 = 0x428a2f98U;
    const uint32_t K1 = 0x71374491U;
    __m128i msg = _mm_set_epi32(0, 0, W1 + K1, W0 + K0);
    efgh = _mm_sha256rnds2_epu32(efgh, abcd, msg);

    alignas(16) uint8_t sbytes[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(sbytes), efgh);
    int bit = sbytes[15] & 1;

    result_bytes[i >> 3] |= static_cast<uint8_t>(bit << (i & 7));
  }
  std::memcpy(&a_out, result_bytes, 16);

                                 }

inline void aes128_encrypt_batch(uint128_t& a_out, const uint128_t* keys,
                                 const uint128_t& y, size_t kappa) {
  __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));

  uint8_t result_bytes[16] = {0};

  for (size_t i = 0; i < kappa; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);

    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);

    alignas(16) uint8_t cipher[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipher), state);

    int bit = cipher[15] & 1;
    result_bytes[i >> 3] |= (bit << (i % 8));
  }

  std::memcpy(&a_out, result_bytes, 16);
}

inline void sha256_encrypt_batch(uint128_t& a_out, const uint128_t* keys,
                                 const uint128_t& y, size_t kappa) {
  __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));

  uint8_t result_bytes[16] = {0};

  for (size_t i = 0; i < kappa; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);
    __m128i x = _mm_xor_si128(y_block, key_block);
    alignas(16) uint32_t wtmp[4];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(wtmp), x);
    uint32_t W0 = wtmp[0];
    uint32_t W1 = wtmp[1];
    __m128i abcd = _mm_set_epi32(0xa54ff53aU, 0x3c6ef372U, 0xbb67ae85U, 0x6a09e667U);
    __m128i efgh = _mm_set_epi32(0x5be0cd19U, 0x1f83d9abU, 0x9b05688cU, 0x510e527fU);

    const uint32_t K0 = 0x428a2f98U;
    const uint32_t K1 = 0x71374491U;
    __m128i msg = _mm_set_epi32(0, 0, W1 + K1, W0 + K0);
    efgh = _mm_sha256rnds2_epu32(efgh, abcd, msg);

    alignas(16) uint8_t sbytes[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(sbytes), efgh);
    int bit = sbytes[15] & 1;

    result_bytes[i >> 3] |= static_cast<uint8_t>(bit << (i & 7));
  }

  std::memcpy(&a_out, result_bytes, 16);
}

inline void blake3_encrypt_batch(uint128_t& a_out, const uint128_t* keys,
                                 const uint128_t& y) {
  uint8_t result_bytes[16] = {0};
  for (size_t i = 0; i < 128; ++i) {
    auto in = yacl::SerializeUint128(keys[i]^y);
    std::vector<uint8_t> out = yacl::crypto::Blake3Hash(1).Update(yacl::ByteContainerView(&in, 1)).CumulativeHash();
    int bit = out[0] & 1;
    result_bytes[i >> 3] |= (bit << (i % 8));
  }
  std::memcpy(&a_out, result_bytes, 16);
}



inline std::vector<bool> GetIntersectionMask(const std::vector<uint128_t>& x,
                                             const std::vector<uint128_t>& y,
                                             std::vector<bool>& mask) {
  std::unordered_set<uint128_t, U128Hasher> y_set;
  y_set.max_load_factor(0.7F);
  y_set.rehash(static_cast<size_t>(std::ceil(y.size() / 0.7)));
  y_set.insert(y.begin(), y.end());
  yacl::parallel_for(0, x.size(), [&](size_t start, size_t end) {
    for (size_t i = start; i < end; ++i) {
      if (y_set.contains(x[i])) {
        mask[i] = true;
      }
    }
  });

  return mask;
}