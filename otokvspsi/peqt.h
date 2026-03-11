#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "coproto/Socket/LocalAsyncSock.h"
#include "coproto/coproto.h"
#include "examples/otokvspsi/debug_logging.h"
#include "examples/otokvspsi/local_comm_stats.h"
#include "examples/otokvspsi/volepsi/GMW/Circuit.h"
#include "examples/otokvspsi/volepsi/GMW/Gmw.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/link/context.h"
#include "yacl/utils/parallel.h"

namespace otokvspsi::peqt {

using Block = uint128_t;

inline const char* RoleName(int rank) { return rank == 0 ? "sender" : "receiver"; }

inline void LogPeqtStep(int rank, const std::string& step) {
  if (!otokvspsi::debug::Enabled()) {
    return;
  }
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);
  std::cout << "[PEQT][" << RoleName(rank) << "] " << step << std::endl;
}

inline void SendAsyncBytes(const std::shared_ptr<yacl::link::Context>& ctx,
                           int dst_rank, const std::string& tag,
                           const void* data, size_t nbytes) {
  ctx->SendAsync(dst_rank, yacl::ByteContainerView(data, nbytes), tag);
}

inline std::vector<uint8_t> RecvBytes(
    const std::shared_ptr<yacl::link::Context>& ctx, int src_rank,
    const std::string& tag) {
  auto buf = ctx->Recv(src_rank, tag);
  std::vector<uint8_t> out(buf.size());
  if (!out.empty()) {
    std::memcpy(out.data(), buf.data(), buf.size());
  }
  return out;
}

inline void SendU64(const std::shared_ptr<yacl::link::Context>& ctx,
                    int dst_rank, const std::string& tag, uint64_t v) {
  SendAsyncBytes(ctx, dst_rank, tag, &v, sizeof(v));
}

inline uint64_t RecvU64(const std::shared_ptr<yacl::link::Context>& ctx,
                        int src_rank, const std::string& tag) {
  auto bytes = RecvBytes(ctx, src_rank, tag);
  YACL_ENFORCE(bytes.size() == sizeof(uint64_t), "RecvU64 size mismatch");
  uint64_t v = 0;
  std::memcpy(&v, bytes.data(), sizeof(v));
  return v;
}

struct LocalSilentSocketEntry {
  std::optional<coproto::LocalAsyncSocket> socks[2];
  size_t claimed = 0;
};

inline coproto::LocalAsyncSocket AcquireLocalSocket(const std::string& tag,
                                                    int rank) {
  static std::mutex mu;
  static std::unordered_map<std::string, LocalSilentSocketEntry> registry;

  std::lock_guard<std::mutex> lock(mu);
  auto& entry = registry[tag];
  if (!entry.socks[0].has_value() && !entry.socks[1].has_value()) {
    auto pair = coproto::LocalAsyncSocket::makePair();
    entry.socks[0].emplace(std::move(pair[0]));
    entry.socks[1].emplace(std::move(pair[1]));
  }

  YACL_ENFORCE(entry.socks[rank].has_value(), "socket tag={} rank={} reused",
               tag, rank);
  auto sock = std::move(*entry.socks[rank]);
  entry.socks[rank].reset();
  entry.claimed += 1;
  if (entry.claimed == 2) {
    registry.erase(tag);
  }
  return sock;
}

inline size_t GmwThreadCount() {
  static const size_t thread_count = [] {
    if (const char* env = std::getenv("OTOKVS_PEQT_GMW_THREADS")) {
      char* end = nullptr;
      auto parsed = std::strtoull(env, &end, 10);
      if (end != env && *end == '\0' && parsed > 0) {
        return static_cast<size_t>(parsed);
      }
    }
    return static_cast<size_t>(1);
  }();
  return thread_count;
}

inline size_t PeqtBatchItemCount() {
  static const size_t batch_items = [] {
    if (const char* env = std::getenv("OTOKVS_PEQT_BATCH_ITEMS")) {
      char* end = nullptr;
      auto parsed = std::strtoull(env, &end, 10);
      if (end != env && *end == '\0' && parsed > 0) {
        return static_cast<size_t>(parsed);
      }
    }
    return static_cast<size_t>(1) << 17;
  }();
  return batch_items;
}

inline size_t PeqtParallelBatchCount() {
  static const size_t parallel_batches = [] {
    if (const char* env = std::getenv("OTOKVS_PEQT_PARALLEL_BATCHES")) {
      char* end = nullptr;
      auto parsed = std::strtoull(env, &end, 10);
      if (end != env && *end == '\0' && parsed > 0) {
        return static_cast<size_t>(parsed);
      }
    }
    const auto hc = std::thread::hardware_concurrency();
    if (hc > 0) {
      return static_cast<size_t>(hc);
    }
    return static_cast<size_t>(4);
  }();
  return parallel_batches;
}

inline size_t GmwTripleBatchSize() {
  static const size_t batch_size = [] {
    if (const char* env = std::getenv("OTOKVS_PEQT_GMW_TRIPLE_BATCH")) {
      char* end = nullptr;
      auto parsed = std::strtoull(env, &end, 10);
      if (end != env && *end == '\0' && parsed > 0) {
        return static_cast<size_t>(parsed);
      }
    }
    return static_cast<size_t>(1) << 20;
  }();
  return batch_size;
}

inline volePSI::Matrix<volePSI::u8> MakeInputMatrix(const uint128_t* my_vec,
                                                    size_t n,
                                                    size_t bit_width) {
  const size_t num_bytes = (bit_width + 7) / 8;
  volePSI::Matrix<volePSI::u8> input;
  input.resize(n, num_bytes);
  if (input.size() != 0) {
    std::memset(input.data(), 0, input.size() * sizeof(volePSI::u8));
  }

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      auto row = input[static_cast<size_t>(idx)];
      std::memcpy(row.data(), &my_vec[idx], num_bytes);
      if ((bit_width & 7U) != 0U) {
        row[num_bytes - 1] &=
            static_cast<uint8_t>((1U << (bit_width & 7U)) - 1U);
      }
    }
  });
  return input;
}

inline void FlushLocalSocket(coproto::Socket& sock) {
  coproto::sync_wait(sock.flush());
}

inline std::vector<bool> EqU128BatchGmw(
    int rank, const uint128_t* my_vec, size_t n, size_t bit_width,
    const std::string& tag_prefix, size_t batch_idx, size_t batch_count) {
  LogPeqtStep(rank, "start equality batch " + std::to_string(batch_idx + 1) +
                        "/" + std::to_string(batch_count) + ", n=" +
                        std::to_string(n) + ", bit_width=" +
                        std::to_string(bit_width) + ", threads=" +
                        std::to_string(GmwThreadCount()));
  if (n == 0) {
    return {};
  }
  YACL_ENFORCE(bit_width > 0 && bit_width <= 128,
               "bit_width must be in [1, 128], got={}", bit_width);

  auto sock = AcquireLocalSocket(tag_prefix, rank);
  auto input = MakeInputMatrix(my_vec, n, bit_width);
  auto cir = volePSI::isZeroCircuit(bit_width);

  volePSI::Gmw gmw;
  gmw.init(n, cir, GmwThreadCount(), rank,
           rank == 0 ? oc::ZeroBlock : oc::OneBlock);
  gmw.setInput(0, input);

  LogPeqtStep(rank, "generate GMW silent triples, batch=" +
                        std::to_string(batch_idx + 1) + "/" +
                        std::to_string(batch_count) + ", total_ots=" +
                        std::to_string(gmw.mNumOts) + ", triple_batch=" +
                        std::to_string(GmwTripleBatchSize()) + ", threads=" +
                        std::to_string(GmwThreadCount()));
  coproto::sync_wait(
      gmw.generateTriple(GmwTripleBatchSize(), GmwThreadCount(), sock));
  FlushLocalSocket(sock);

  LogPeqtStep(rank, "run GMW equality circuit, batch=" +
                        std::to_string(batch_idx + 1) + "/" +
                        std::to_string(batch_count) + ", rounds=" +
                        std::to_string(gmw.numRounds()));
  coproto::sync_wait(gmw.run(sock));
  FlushLocalSocket(sock);
  otokvspsi::local_comm_stats::Record(rank, sock);

  volePSI::Matrix<volePSI::u8> out;
  out.resize(n, 1);
  gmw.getOutput(0, out);

  std::vector<bool> eq_share(n, false);
  for (size_t i = 0; i < n; ++i) {
    eq_share[i] = static_cast<bool>(out[i][0] & 1U);
  }
  LogPeqtStep(rank, "finish equality batch " + std::to_string(batch_idx + 1) +
                        "/" + std::to_string(batch_count));
  return eq_share;
}

inline std::vector<bool> EqU128Vec2PCPreRot(
    const std::shared_ptr<yacl::link::Context>& ctx, int rank,
    const std::vector<uint128_t>& my_vec, size_t bit_width,
    const std::string& tag_prefix) {
  LogPeqtStep(rank, "start equality reduction, n=" +
                        std::to_string(my_vec.size()) + ", bit_width=" +
                        std::to_string(bit_width) + ", impl=volepsi_gmw");
  const uint64_t my_n = static_cast<uint64_t>(my_vec.size());
  const int peer = 1 - rank;
  if (rank == 0) {
    SendU64(ctx, peer, tag_prefix + "_n01", my_n);
    YACL_ENFORCE(RecvU64(ctx, peer, tag_prefix + "_n10") == my_n,
                 "Size mismatch");
  } else {
    SendU64(ctx, peer, tag_prefix + "_n10", my_n);
    YACL_ENFORCE(RecvU64(ctx, peer, tag_prefix + "_n01") == my_n,
                 "Size mismatch");
  }

  const size_t n = my_vec.size();
  if (n == 0) {
    return {};
  }
  YACL_ENFORCE(bit_width > 0 && bit_width <= 128,
               "bit_width must be in [1, 128], got={}", bit_width);
  const size_t batch_items = std::max<size_t>(1, PeqtBatchItemCount());
  const size_t batch_count = (n + batch_items - 1) / batch_items;
  const size_t parallel_batches =
      std::min(batch_count, std::max<size_t>(1, PeqtParallelBatchCount()));
  LogPeqtStep(rank, "batch schedule: batch_items=" +
                        std::to_string(batch_items) + ", batch_count=" +
                        std::to_string(batch_count) + ", parallel_batches=" +
                        std::to_string(parallel_batches) + ", gmw_threads=" +
                        std::to_string(GmwThreadCount()));

  std::vector<bool> eq_share(n, false);
  std::vector<std::future<std::vector<bool>>> inflight(batch_count);
  size_t launched = 0;
  size_t completed = 0;

  while (completed < batch_count) {
    while (launched < batch_count &&
           (launched - completed) < parallel_batches) {
      const size_t batch_idx = launched++;
      const size_t offset = batch_idx * batch_items;
      const size_t batch_n = std::min(batch_items, n - offset);
      inflight[batch_idx] = std::async(
          std::launch::async,
          [&, batch_idx, offset, batch_n]() -> std::vector<bool> {
            return EqU128BatchGmw(
                rank, my_vec.data() + offset, batch_n, bit_width,
                tag_prefix + "_GMW_B" + std::to_string(batch_idx), batch_idx,
                batch_count);
          });
    }

    const size_t batch_idx = completed++;
    const size_t offset = batch_idx * batch_items;
    auto batch_share = inflight[batch_idx].get();
    for (size_t i = 0; i < batch_share.size(); ++i) {
      eq_share[offset + i] = batch_share[i];
    }
  }

  LogPeqtStep(rank, "finish equality reduction");
  return eq_share;
}

}  // namespace otokvspsi::peqt
