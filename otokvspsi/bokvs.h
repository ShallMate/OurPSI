#pragma once

#include <cmath>
#include <cstdint>
#include <vector>

#include "examples/otokvspsi/okvs/galois128.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

class OKVSBK {
 public:
  OKVSBK(int64_t n, int64_t w, double e)
      : n_(n),
        m_(std::ceil(n * e)),
        w_(w),
        r_(m_ - w),
        band_length_(w),
        e_(e),
        p_(m_, 0) {
    YACL_ENFORCE(w_ <= kMaxBandBits,
                 "band length exceeds max capacity: w={}, max={}", w_,
                 kMaxBandBits);
  }

  int64_t getN() const { return n_; }
  int64_t getM() const { return m_; }
  int64_t getW() const { return w_; }
  int64_t getR() const { return r_; }
  double getE() const { return e_; }

  bool Encode(std::vector<uint128_t> keys, std::vector<uint128_t> values);
  void Decode(std::vector<uint128_t> keys, std::vector<uint128_t>& values);
  void DecodeOtherP(std::vector<uint128_t> keys, std::vector<uint128_t>& values,
                    const std::vector<uint128_t>& p) const;
  void DecodeDifflenP(std::vector<uint128_t> keys,
                      std::vector<uint128_t>& values,
                      const std::vector<uint128_t>& p) const;
  void Mul(okvs::Galois128 delta_gf128);

 private:
  static constexpr int64_t kMaxBandBits = 128 * 6;
  int64_t n_;
  int64_t m_;
  int64_t w_;
  int64_t r_;
  int64_t band_length_;
  double e_;

 public:
  std::vector<uint128_t> p_;
};
