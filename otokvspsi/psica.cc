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
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "examples/otokvspsi/cpsi.h"
#include "examples/otokvspsi/debug_logging.h"
#include "examples/otokvspsi/local_comm_stats.h"
#include "examples/otokvspsi/psica.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace oc = osuCrypto;

namespace psica {

namespace {

const char* RoleName(int rank) { return rank == 0 ? "sender" : "receiver"; }

void LogPsiCaStep(const std::shared_ptr<yacl::link::Context>& ctx,
                  const std::string& step) {
  if (!otokvspsi::debug::Enabled()) {
    return;
  }
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);
  std::cout << "[PSI-CA][" << RoleName(ctx->Rank()) << "] " << step
            << std::endl;
}

void SendAsyncBytes(const std::shared_ptr<yacl::link::Context>& ctx,
                    int dst_rank, const std::string& tag, const void* data,
                    size_t nbytes) {
  ctx->SendAsync(dst_rank, yacl::ByteContainerView(data, nbytes), tag);
}

std::vector<uint8_t> RecvBytes(
    const std::shared_ptr<yacl::link::Context>& ctx, int src_rank,
    const std::string& tag) {
  auto buf = ctx->Recv(src_rank, tag);
  std::vector<uint8_t> out(buf.size());
  if (!out.empty()) {
    std::memcpy(out.data(), buf.data(), buf.size());
  }
  return out;
}

void SendU64(const std::shared_ptr<yacl::link::Context>& ctx, int dst_rank,
             const std::string& tag, uint64_t v) {
  SendAsyncBytes(ctx, dst_rank, tag, &v, sizeof(v));
}

uint64_t RecvU64(const std::shared_ptr<yacl::link::Context>& ctx, int src_rank,
                 const std::string& tag) {
  auto bytes = RecvBytes(ctx, src_rank, tag);
  YACL_ENFORCE(bytes.size() == sizeof(uint64_t), "RecvU64 size mismatch");
  uint64_t v = 0;
  std::memcpy(&v, bytes.data(), sizeof(v));
  return v;
}

struct LocalOtSocketEntry {
  std::optional<coproto::LocalAsyncSocket> socks[2];
  size_t claimed = 0;
};

coproto::LocalAsyncSocket AcquireLocalSocket(const std::string& tag, int rank) {
  static std::mutex mu;
  static std::unordered_map<std::string, LocalOtSocketEntry> registry;

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

void FlushLocalSocket(coproto::Socket& sock) { coproto::sync_wait(sock.flush()); }

size_t ParseEnvPositive(const char* name, size_t fallback) {
  if (const char* env = std::getenv(name)) {
    char* end = nullptr;
    auto parsed = std::strtoull(env, &end, 10);
    if (end != env && *end == '\0' && parsed > 0) {
      return static_cast<size_t>(parsed);
    }
  }
  return fallback;
}

size_t PsiCaOtThreadCount() {
  static const size_t thread_count = [] {
    const auto hc = std::thread::hardware_concurrency();
    return ParseEnvPositive("OTOKVS_PSICA_OT_THREADS",
                            hc == 0 ? static_cast<size_t>(4)
                                    : static_cast<size_t>(hc));
  }();
  return thread_count;
}

size_t PsiCaBatchItemCount(size_t total) {
  return ParseEnvPositive("OTOKVS_PSICA_BATCH_ITEMS", std::max<size_t>(1, total));
}

size_t PsiCaParallelBatchCount(size_t batch_count) {
  return std::min(batch_count,
                  ParseEnvPositive("OTOKVS_PSICA_PARALLEL_BATCHES",
                                   static_cast<size_t>(1)));
}

inline oc::block U64ToBlock(uint64_t value) { return oc::toBlock(0, value); }

inline uint64_t BlockToU64(const oc::block& blk) {
  return static_cast<uint64_t>(blk.get<oc::u64>(0));
}

uint64_t CountSharedBitsBatchOt(const std::shared_ptr<yacl::link::Context>& ctx,
                                int rank,
                                const std::vector<uint64_t>& shares,
                                size_t offset, size_t count,
                                const std::string& tag_prefix,
                                size_t batch_idx, size_t batch_count) {
  LogPsiCaStep(ctx, "start B2A batch " + std::to_string(batch_idx + 1) + "/" +
                        std::to_string(batch_count) + ", n=" +
                        std::to_string(count) + ", ot_threads=" +
                        std::to_string(PsiCaOtThreadCount()));
  if (count == 0) {
    return 0;
  }

  auto sock = AcquireLocalSocket(tag_prefix, rank);
  oc::PRNG prng(oc::sysRandomSeed());

  if (rank == 0) {
    oc::SilentOtExtSender ot;
    ot.configure(count, 2, PsiCaOtThreadCount(), oc::SilentSecType::SemiHonest);
    coproto::sync_wait(ot.genBaseOts(prng, sock));
    FlushLocalSocket(sock);

    oc::AlignedUnVector<std::array<oc::block, 2>> send_msgs(count);
    uint64_t local_sum = 0;
    for (size_t i = 0; i < count; ++i) {
      const uint64_t share_bit = shares[offset + i] & 1ULL;
      const uint64_t rand_share = prng.get<uint64_t>();
      local_sum += rand_share;
      send_msgs[i][0] = U64ToBlock(share_bit - rand_share);
      send_msgs[i][1] = U64ToBlock((1ULL - share_bit) - rand_share);
    }

    LogPsiCaStep(ctx, "run silent OT B2A sender, batch=" +
                          std::to_string(batch_idx + 1) + "/" +
                          std::to_string(batch_count));
    coproto::sync_wait(ot.sendChosen(
        oc::span<std::array<oc::block, 2>>(send_msgs.data(), send_msgs.size()),
        prng, sock));
    FlushLocalSocket(sock);
    otokvspsi::local_comm_stats::Record(rank, sock);
    return local_sum;
  }

  oc::SilentOtExtReceiver ot;
  ot.configure(count, 2, PsiCaOtThreadCount(), oc::SilentSecType::SemiHonest);
  coproto::sync_wait(ot.genBaseOts(prng, sock));
  FlushLocalSocket(sock);

  oc::BitVector choices(count);
  for (size_t i = 0; i < count; ++i) {
    choices[i] = static_cast<uint8_t>(shares[offset + i] & 1ULL);
  }

  oc::AlignedUnVector<oc::block> recv_msgs(count);
  LogPsiCaStep(ctx, "run silent OT B2A receiver, batch=" +
                        std::to_string(batch_idx + 1) + "/" +
                        std::to_string(batch_count));
  coproto::sync_wait(ot.receiveChosen(
      choices, oc::span<oc::block>(recv_msgs.data(), recv_msgs.size()), prng,
      sock));
  FlushLocalSocket(sock);
  otokvspsi::local_comm_stats::Record(rank, sock);

  uint64_t local_sum = 0;
  for (size_t i = 0; i < count; ++i) {
    local_sum += BlockToU64(recv_msgs[i]);
  }
  return local_sum;
}

uint64_t CountSharedBitsToReceiver(
    const std::shared_ptr<yacl::link::Context>& ctx, int rank,
    const std::vector<uint64_t>& shares, const std::string& tag_prefix) {
  const uint64_t my_n = static_cast<uint64_t>(shares.size());
  const int peer = 1 - rank;
  if (rank == 0) {
    SendU64(ctx, peer, tag_prefix + "_count_n01", my_n);
    YACL_ENFORCE(RecvU64(ctx, peer, tag_prefix + "_count_n10") == my_n,
                 "Size mismatch");
  } else {
    SendU64(ctx, peer, tag_prefix + "_count_n10", my_n);
    YACL_ENFORCE(RecvU64(ctx, peer, tag_prefix + "_count_n01") == my_n,
                 "Size mismatch");
  }

  if (shares.empty()) {
    return 0;
  }

  const size_t batch_items = std::max<size_t>(1, PsiCaBatchItemCount(shares.size()));
  const size_t batch_count = (shares.size() + batch_items - 1) / batch_items;
  const size_t parallel_batches = PsiCaParallelBatchCount(batch_count);
  LogPsiCaStep(ctx, "B2A schedule: batch_items=" + std::to_string(batch_items) +
                        ", batch_count=" + std::to_string(batch_count) +
                        ", parallel_batches=" +
                        std::to_string(parallel_batches));

  std::vector<std::future<uint64_t>> inflight(batch_count);
  size_t launched = 0;
  size_t completed = 0;
  uint64_t total = 0;

  while (completed < batch_count) {
    while (launched < batch_count &&
           (launched - completed) < parallel_batches) {
      const size_t batch_idx = launched++;
      const size_t offset = batch_idx * batch_items;
      const size_t batch_n = std::min(batch_items, shares.size() - offset);
      inflight[batch_idx] = std::async(
          std::launch::async, [&, batch_idx, offset, batch_n]() -> uint64_t {
            return CountSharedBitsBatchOt(
                ctx, rank, shares, offset, batch_n,
                tag_prefix + "_B2A_B" + std::to_string(batch_idx), batch_idx,
                batch_count);
          });
    }

    const size_t batch_idx = completed++;
    const uint64_t local_sum = inflight[batch_idx].get();
    const std::string reveal_tag =
        tag_prefix + "_SUM_REVEAL_" + std::to_string(batch_idx);
    if (rank == 0) {
      SendU64(ctx, peer, reveal_tag, local_sum);
    } else {
      const uint64_t peer_sum = RecvU64(ctx, peer, reveal_tag);
      total += local_sum + peer_sum;
    }
  }

  return rank == 1 ? total : 0;
}

uint64_t RunCardinalityFromPackedShares(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint64_t>& shares, const std::string& tag) {
  LogPsiCaStep(ctx, "enter B2A cardinality, share_count=" +
                        std::to_string(shares.size()));
  const auto card = CountSharedBitsToReceiver(ctx, ctx->Rank(), shares, tag);
  LogPsiCaStep(ctx, "leave B2A cardinality");
  return card;
}

}  // namespace

uint64_t CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                    okvs::Baxos baxos2, uint32_t cuckoolen,
                    std::vector<uint64_t>& items_av) {
  auto shares = cpsi::CPsiSend(ctx, elem_hashes, baxos, baxos2, cuckoolen,
                               items_av);
  return RunCardinalityFromPackedShares(ctx, shares, "OTOKVS_PSICA_AES_RR22");
}

uint64_t CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                    okvs::Baxos baxos2) {
  auto shares = cpsi::CPsiRecv(ctx, elem_hashes, baxos, baxos2);
  return RunCardinalityFromPackedShares(ctx, shares, "OTOKVS_PSICA_AES_RR22");
}

uint64_t SHA2CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                        okvs::Baxos baxos2, uint32_t cuckoolen,
                        std::vector<uint64_t>& items_av) {
  auto shares = cpsi::SHA2CPsiSend(ctx, elem_hashes, baxos, baxos2, cuckoolen,
                                   items_av);
  return RunCardinalityFromPackedShares(ctx, shares, "OTOKVS_PSICA_SHA2_RR22");
}

uint64_t SHA2CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                        okvs::Baxos baxos2) {
  auto shares = cpsi::SHA2CPsiRecv(ctx, elem_hashes, baxos, baxos2);
  return RunCardinalityFromPackedShares(ctx, shares, "OTOKVS_PSICA_SHA2_RR22");
}

uint64_t CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes,
                    band_okvs::BandOkvs baxos, band_okvs::BandOkvs baxos2,
                    uint32_t cuckoolen, std::vector<uint64_t>& items_av) {
  auto shares = cpsi::CPsiSend(ctx, elem_hashes, baxos, baxos2, cuckoolen,
                               items_av);
  return RunCardinalityFromPackedShares(ctx, shares,
                                        "OTOKVS_PSICA_AES_BANDOKVS");
}

uint64_t CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes,
                    band_okvs::BandOkvs baxos, band_okvs::BandOkvs baxos2) {
  auto shares = cpsi::CPsiRecv(ctx, elem_hashes, baxos, baxos2);
  return RunCardinalityFromPackedShares(ctx, shares,
                                        "OTOKVS_PSICA_AES_BANDOKVS");
}

uint64_t SHA2CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes,
                        band_okvs::BandOkvs baxos, band_okvs::BandOkvs baxos2,
                        uint32_t cuckoolen, std::vector<uint64_t>& items_av) {
  auto shares = cpsi::SHA2CPsiSend(ctx, elem_hashes, baxos, baxos2, cuckoolen,
                                   items_av);
  return RunCardinalityFromPackedShares(ctx, shares,
                                        "OTOKVS_PSICA_SHA2_BANDOKVS");
}

uint64_t SHA2CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes,
                        band_okvs::BandOkvs baxos, band_okvs::BandOkvs baxos2) {
  auto shares = cpsi::SHA2CPsiRecv(ctx, elem_hashes, baxos, baxos2);
  return RunCardinalityFromPackedShares(ctx, shares,
                                        "OTOKVS_PSICA_SHA2_BANDOKVS");
}

}  // namespace psica
