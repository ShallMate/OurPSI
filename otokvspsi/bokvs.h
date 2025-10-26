

#pragma once

#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

#include "examples/otokvspsi/okvs/galois128.h"
#include "yacl/base/int128.h"

struct Row {
  int64_t pos;
  int64_t bpos;
  std::vector<std::uint8_t> row;
  uint128_t value;
};

inline uint128_t BytesToUint128(std::vector<uint8_t> bytes) {
  uint128_t value = 0;
  for (int i = 0; i < 16; ++i) {
    value = (value << 8) | bytes[i];
  }
  return value;
}

class OKVSBK {
 public:
  OKVSBK(int64_t n, int64_t w, double e)
      : n_(n),
        m_(std::ceil(n * e)),
        w_(w),
        r_(m_ - w),
        b_(w / 8),
        e_(e),
        p_(m_, 0) {}

  int64_t getN() const { return n_; }

  int64_t getM() const { return m_; }

  int64_t getW() const { return w_; }

  int64_t getR() const { return r_; }

  double getE() const { return e_; }

  double getB() const { return b_; }

  bool Encode(std::vector<uint128_t> keys, std::vector<uint128_t> values);
  void Decode(std::vector<uint128_t> keys, std::vector<uint128_t>& values);
  void DecodeOtherP(std::vector<uint128_t> keys, std::vector<uint128_t>& values,
                    std::vector<uint128_t> p) const;
  void DecodeDifflenP(std::vector<uint128_t> keys,
                      std::vector<uint128_t>& values,
                      std::vector<uint128_t> p) const;
  void Mul(okvs::Galois128 delta_gf128);

 private:
  int64_t n_;
  int64_t m_;
  int64_t w_;
  int64_t r_;
  int64_t b_;
  double e_;

 public:
  std::vector<uint128_t> p_;
};
