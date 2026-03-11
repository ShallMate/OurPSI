

#pragma once

#include <wmmintrin.h>

#include <cstddef>
#include <cstring>
#include <vector>

#include "examples/otokvspsi/bandokvs/utils.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

inline uint64_t GetHash(size_t idx, uint128_t code) {
  uint64_t aligned_u64;
  memcpy(&aligned_u64, reinterpret_cast<const uint8_t*>(&code) + idx * 2,
         sizeof(aligned_u64));
  return aligned_u64;
}

inline uint128_t Oracle(size_t idx, __m128i key_block, __m128i y_block) {
  __m128i idx_block = _mm_cvtsi64_si128(idx);

  __m128i msg = _mm_xor_si128(y_block, idx_block);
  __m128i state = _mm_xor_si128(msg, key_block);

  state = _mm_aesenc_si128(state, key_block);
  state = _mm_aesenclast_si128(state, key_block);

  uint128_t out;
  _mm_storeu_si128(reinterpret_cast<__m128i*>(&out), state);
  return out;
}

class CuckooHash {
 public:
  explicit CuckooHash(int cuckoosize)
      : cuckoosize_(cuckoosize),
        cuckoolen_(static_cast<uint32_t>(cuckoosize_ * 1.27)) {
    if (cuckoosize_ <= 0) {
      throw std::invalid_argument("cuckoosize must be positive");
    }
    bins_.resize(cuckoolen_);
  }

  void Insert(std::vector<uint128_t> inputs) {
    if (cuckoosize_ != inputs.size()) {
      throw std::invalid_argument("cuckoosize must be positive");
    }
    hash_index_.resize(cuckoolen_, 0);
    item_index_.assign(cuckoolen_, kEmptyIndex);
    std::vector<size_t> input_index(inputs.size(), 0);
    for (size_t i = 0; i < inputs.size(); ++i) {
      input_index[i] = i;
    }
    for (size_t i = 0; i < cuckoosize_; ++i) {
      uint8_t old_hash_id = 1;
      size_t j = 0;
      for (; j < maxiter_; ++j) {
        uint64_t h = GetHash(old_hash_id, inputs[i]) % cuckoolen_;
        uint8_t* hash_id_address = &hash_index_[h];
        uint128_t* key_index_address = &bins_[h];
        size_t* item_index_address = &item_index_[h];
        if (*hash_id_address == empty_) {
          *hash_id_address = old_hash_id;
          *key_index_address = inputs[i];
          *item_index_address = input_index[i];
          break;
        } else {
          std::swap(inputs[i], *key_index_address);
          std::swap(old_hash_id, *hash_id_address);
          std::swap(input_index[i], *item_index_address);
          old_hash_id = old_hash_id % 3 + 1;
        }
      }
      if (j == maxiter_) {
        throw std::runtime_error("insert failed, " + std::to_string(i));
      }
    }
  }
  void Transform(uint128_t seed) {
    __m128i key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&seed));
    yacl::parallel_for(0, bins_.size(), [&](int64_t begin, int64_t end) {
      for (int64_t idx = begin; idx < end; ++idx) {
        if (bins_[idx] == 0 && hash_index_[idx] == 0) {
          bins_[idx] = yacl::crypto::FastRandU128();
        } else {
          __m128i y_block =
              _mm_loadu_si128(reinterpret_cast<const __m128i*>(&bins_[idx]));
          bins_[idx] = Oracle(hash_index_[idx], key_block, y_block);
        }
      }
    });
  }

  std::vector<uint128_t> bins_;
  std::vector<uint8_t> hash_index_;
  std::vector<size_t> item_index_;
  size_t cuckoosize_;
  uint32_t cuckoolen_;

 private:
  const uint8_t empty_ = 0;
  const size_t maxiter_ = 500;
  static constexpr size_t kEmptyIndex = static_cast<size_t>(-1);
};
