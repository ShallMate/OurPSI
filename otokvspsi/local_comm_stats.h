#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "coproto/Socket/Socket.h"

namespace otokvspsi::local_comm_stats {

struct CommStats {
  std::array<uint64_t, 2> sent = {0, 0};
  std::array<uint64_t, 2> recv = {0, 0};
};

inline std::array<std::atomic<uint64_t>, 2>& SentCounters() {
  static std::array<std::atomic<uint64_t>, 2> counters = {
      std::atomic<uint64_t>(0), std::atomic<uint64_t>(0)};
  return counters;
}

inline std::array<std::atomic<uint64_t>, 2>& RecvCounters() {
  static std::array<std::atomic<uint64_t>, 2> counters = {
      std::atomic<uint64_t>(0), std::atomic<uint64_t>(0)};
  return counters;
}

inline void Reset() {
  for (auto& counter : SentCounters()) {
    counter.store(0, std::memory_order_relaxed);
  }
  for (auto& counter : RecvCounters()) {
    counter.store(0, std::memory_order_relaxed);
  }
}

inline void Record(int rank, uint64_t sent, uint64_t recv) {
  if (rank < 0 || rank >= 2) {
    return;
  }
  SentCounters()[static_cast<size_t>(rank)].fetch_add(sent,
                                                      std::memory_order_relaxed);
  RecvCounters()[static_cast<size_t>(rank)].fetch_add(recv,
                                                      std::memory_order_relaxed);
}

inline void Record(int rank, coproto::Socket& sock) {
  Record(rank, static_cast<uint64_t>(sock.bytesSent()),
         static_cast<uint64_t>(sock.bytesReceived()));
}

inline CommStats Snapshot() {
  CommStats stats;
  for (size_t i = 0; i < 2; ++i) {
    stats.sent[i] = SentCounters()[i].load(std::memory_order_relaxed);
    stats.recv[i] = RecvCounters()[i].load(std::memory_order_relaxed);
  }
  return stats;
}

}  // namespace otokvspsi::local_comm_stats
