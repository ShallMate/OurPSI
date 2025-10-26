

#pragma once

#include <cstdint>

namespace okvs {

class SimpleIndex {
 public:
  static uint64_t GetBinSize(uint64_t num_bins, uint64_t num_balls,
                             uint64_t stat_sec_param, bool approx = true);
};

}  // namespace okvs
