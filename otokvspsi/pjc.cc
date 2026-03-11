#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <future>
#include <immintrin.h>
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
#include "examples/otokvspsi/cuckoohash.h"
#include "examples/otokvspsi/debug_logging.h"
#include "examples/otokvspsi/local_comm_stats.h"
#include "examples/otokvspsi/pjc.h"
#include "examples/otokvspsi/peqt.h"
#include "examples/otokvspsi/utils.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

namespace oc = osuCrypto;

namespace pjc {

constexpr size_t KAPPA = 128;

using namespace yacl::crypto;

namespace {

const char* RoleName(int rank) { return rank == 0 ? "sender" : "receiver"; }

void LogPjcStep(const std::shared_ptr<yacl::link::Context>& ctx,
                const std::string& step) {
  if (!otokvspsi::debug::Enabled()) {
    return;
  }
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);
  std::cout << "[PJC][" << RoleName(ctx->Rank()) << "] " << step << std::endl;
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

void SendU64Vector(const std::shared_ptr<yacl::link::Context>& ctx, int dst_rank,
                   const std::string& tag,
                   const std::vector<uint64_t>& values) {
  SendAsyncBytes(ctx, dst_rank, tag, values.data(),
                 values.size() * sizeof(uint64_t));
}

uint64_t RecvU64(const std::shared_ptr<yacl::link::Context>& ctx, int src_rank,
                 const std::string& tag) {
  auto bytes = RecvBytes(ctx, src_rank, tag);
  YACL_ENFORCE(bytes.size() == sizeof(uint64_t), "RecvU64 size mismatch");
  uint64_t v = 0;
  std::memcpy(&v, bytes.data(), sizeof(v));
  return v;
}

std::vector<uint64_t> RecvU64Vector(
    const std::shared_ptr<yacl::link::Context>& ctx, int src_rank,
    const std::string& tag, size_t expected_size) {
  auto bytes = RecvBytes(ctx, src_rank, tag);
  YACL_ENFORCE(bytes.size() == expected_size * sizeof(uint64_t),
               "RecvU64Vector size mismatch: {} vs {}", bytes.size(),
               expected_size * sizeof(uint64_t));
  std::vector<uint64_t> values(expected_size, 0);
  if (!values.empty()) {
    std::memcpy(values.data(), bytes.data(), bytes.size());
  }
  return values;
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

size_t PjcOtThreadCount() {
  static const size_t thread_count = [] {
    return ParseEnvPositive("OTOKVS_PJC_OT_THREADS", static_cast<size_t>(1));
  }();
  return thread_count;
}

size_t PjcBatchItemCount(size_t total) {
  static const size_t batch_items = [] {
    return ParseEnvPositive("OTOKVS_PJC_BATCH_ITEMS",
                            static_cast<size_t>(1) << 15);
  }();
  return std::min(std::max<size_t>(1, total), batch_items);
}

size_t PjcParallelBatchCount(size_t batch_count) {
  const auto hc = std::thread::hardware_concurrency();
  const auto fallback =
      hc == 0 ? static_cast<size_t>(4)
              : std::max<size_t>(1, static_cast<size_t>(hc) / 2);
  return std::min(batch_count,
                  ParseEnvPositive("OTOKVS_PJC_PARALLEL_BATCHES", fallback));
}

inline oc::block U64ToBlock(uint64_t value) { return oc::toBlock(0, value); }

inline uint64_t BlockToU64(const oc::block& blk) {
  return static_cast<uint64_t>(blk.get<oc::u64>(0));
}

inline uint128_t PackHiLo(uint64_t hi, uint64_t lo) {
  return (static_cast<uint128_t>(hi) << 64) | static_cast<uint128_t>(lo);
}

std::vector<uint128_t> LiftU64ToU128(const std::vector<uint64_t>& values) {
  std::vector<uint128_t> lifted(values.size());
  yacl::parallel_for(0, values.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      lifted[idx] = static_cast<uint128_t>(values[idx]);
    }
  });
  return lifted;
}

std::vector<uint64_t> ExtractLow64(const std::vector<uint128_t>& values) {
  std::vector<uint64_t> lo64(values.size(), 0);
  yacl::parallel_for(0, values.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      lo64[idx] = static_cast<uint64_t>(values[idx]);
    }
  });
  return lo64;
}

std::vector<uint64_t> RunPeqtAndPackShares(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint64_t>& values, const std::string& tag) {
  LogPjcStep(ctx, "enter PEQT, value_count=" + std::to_string(values.size()));
  auto lifted = LiftU64ToU128(values);
  auto eq_share =
      otokvspsi::peqt::EqU128Vec2PCPreRot(ctx, ctx->Rank(), lifted, 64, tag);

  std::vector<uint64_t> packed(eq_share.size(), 0);
  yacl::parallel_for(0, eq_share.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      packed[idx] = eq_share[idx] ? 1 : 0;
    }
  });
  LogPjcStep(ctx, "leave PEQT");
  return packed;
}

std::vector<uint64_t> ExtractHi64AndRunPeqt(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& values, const std::string& tag) {
  LogPjcStep(ctx, "extract high 64 bits for PEQT");
  std::vector<uint64_t> hi64(values.size(), 0);
  yacl::parallel_for(0, values.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      hi64[idx] = static_cast<uint64_t>(values[idx] >> 64);
    }
  });
  return RunPeqtAndPackShares(ctx, hi64, tag);
}

std::vector<uint64_t> BuildReceiverSlotValues(
    const CuckooHash& table, const std::vector<uint64_t>& items_av) {
  std::vector<uint64_t> slot_values(table.cuckoolen_, 0);
  yacl::parallel_for(0, table.cuckoolen_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      const size_t item_index = table.item_index_[static_cast<size_t>(idx)];
      if (item_index < items_av.size()) {
        slot_values[static_cast<size_t>(idx)] = items_av[item_index];
      }
    }
  });
  return slot_values;
}

uint64_t MultiplyBitShareByValueShareDirection(
    int rank, const std::vector<uint64_t>& bit_shares,
    const std::vector<uint64_t>& value_shares, size_t offset, size_t count,
    int value_holder_rank, const std::string& tag) {
  if (count == 0) {
    return 0;
  }

  auto sock = AcquireLocalSocket(tag, rank);
  oc::PRNG prng(oc::sysRandomSeed());

  if (rank == value_holder_rank) {
    oc::SilentOtExtSender ot;
    ot.configure(count, 2, PjcOtThreadCount(), oc::SilentSecType::SemiHonest);
    coproto::sync_wait(ot.genBaseOts(prng, sock));
    FlushLocalSocket(sock);

    oc::AlignedUnVector<std::array<oc::block, 2>> send_msgs(count);
    uint64_t local_sum = 0;
    for (size_t i = 0; i < count; ++i) {
      const uint64_t bit = bit_shares[offset + i] & 1ULL;
      const uint64_t value = value_shares[offset + i];
      const uint64_t mask = prng.get<uint64_t>();
      const uint64_t m0 = bit == 0 ? 0 : value;
      const uint64_t m1 = bit == 0 ? value : 0;
      local_sum += mask;
      send_msgs[i][0] = U64ToBlock(m0 - mask);
      send_msgs[i][1] = U64ToBlock(m1 - mask);
    }

    coproto::sync_wait(ot.sendChosen(
        oc::span<std::array<oc::block, 2>>(send_msgs.data(), send_msgs.size()),
        prng, sock));
    FlushLocalSocket(sock);
    otokvspsi::local_comm_stats::Record(rank, sock);
    return local_sum;
  }

  oc::SilentOtExtReceiver ot;
  ot.configure(count, 2, PjcOtThreadCount(), oc::SilentSecType::SemiHonest);
  coproto::sync_wait(ot.genBaseOts(prng, sock));
  FlushLocalSocket(sock);

  oc::BitVector choices(count);
  for (size_t i = 0; i < count; ++i) {
    choices[i] = static_cast<uint8_t>(bit_shares[offset + i] & 1ULL);
  }

  oc::AlignedUnVector<oc::block> recv_msgs(count);
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

std::vector<uint64_t> MultiplySenderShareByReceiverValueOt(
    const std::shared_ptr<yacl::link::Context>& ctx, int rank,
    const std::vector<uint64_t>& sender_value_shares,
    const std::vector<uint64_t>& receiver_plain_values, size_t offset,
    size_t count, const std::string& tag, size_t batch_idx,
    size_t batch_count) {
  LogPjcStep(ctx, "start sender-share x receiver-value batch " +
                      std::to_string(batch_idx + 1) + "/" +
                      std::to_string(batch_count) + ", n=" +
                      std::to_string(count) + ", ot_threads=" +
                      std::to_string(PjcOtThreadCount()));
  if (count == 0) {
    return {};
  }

  const size_t total_ots = count * 64;
  auto sock = AcquireLocalSocket(tag, rank);
  oc::PRNG prng(oc::sysRandomSeed());
  std::vector<uint64_t> product_share(count, 0);

  if (rank == 0) {
    oc::SilentOtExtSender ot;
    ot.configure(total_ots, 2, PjcOtThreadCount(),
                 oc::SilentSecType::SemiHonest);
    coproto::sync_wait(ot.genBaseOts(prng, sock));
    FlushLocalSocket(sock);

    oc::AlignedUnVector<std::array<oc::block, 2>> send_msgs(total_ots);
    for (size_t i = 0; i < count; ++i) {
      const uint64_t value = sender_value_shares[offset + i];
      for (size_t bit = 0; bit < 64; ++bit) {
        const size_t ot_idx = i * 64 + bit;
        const uint64_t mask = prng.get<uint64_t>();
        product_share[i] += mask;
        send_msgs[ot_idx][0] = U64ToBlock(0ULL - mask);
        send_msgs[ot_idx][1] = U64ToBlock((value << bit) - mask);
      }
    }

    coproto::sync_wait(ot.sendChosen(
        oc::span<std::array<oc::block, 2>>(send_msgs.data(), send_msgs.size()),
        prng, sock));
    FlushLocalSocket(sock);
    otokvspsi::local_comm_stats::Record(rank, sock);
    return product_share;
  }

  oc::SilentOtExtReceiver ot;
  ot.configure(total_ots, 2, PjcOtThreadCount(), oc::SilentSecType::SemiHonest);
  coproto::sync_wait(ot.genBaseOts(prng, sock));
  FlushLocalSocket(sock);

  oc::BitVector choices(total_ots);
  for (size_t i = 0; i < count; ++i) {
    const uint64_t value = receiver_plain_values[offset + i];
    for (size_t bit = 0; bit < 64; ++bit) {
      choices[i * 64 + bit] = static_cast<uint8_t>((value >> bit) & 1ULL);
    }
  }

  oc::AlignedUnVector<oc::block> recv_msgs(total_ots);
  coproto::sync_wait(ot.receiveChosen(
      choices, oc::span<oc::block>(recv_msgs.data(), recv_msgs.size()), prng,
      sock));
  FlushLocalSocket(sock);
  otokvspsi::local_comm_stats::Record(rank, sock);

  for (size_t i = 0; i < count; ++i) {
    uint64_t value = 0;
    for (size_t bit = 0; bit < 64; ++bit) {
      value += BlockToU64(recv_msgs[i * 64 + bit]);
    }
    product_share[i] = value;
  }
  return product_share;
}

uint64_t SumReceiverHeldValuesBatchOt(
    const std::shared_ptr<yacl::link::Context>& ctx, int rank,
    const std::vector<uint64_t>& bit_shares,
    const std::vector<uint64_t>& receiver_values, size_t offset, size_t count,
    const std::string& tag_prefix, const std::string& label, size_t batch_idx,
    size_t batch_count) {
  LogPjcStep(ctx, "start " + label + " batch " +
                      std::to_string(batch_idx + 1) + "/" +
                      std::to_string(batch_count) + ", n=" +
                      std::to_string(count) + ", ot_threads=" +
                      std::to_string(PjcOtThreadCount()));
  return MultiplyBitShareByValueShareDirection(
      rank, bit_shares, receiver_values, offset, count, 1,
      tag_prefix + "_RECEIVER_VALUE");
}

uint64_t SumReceiverHeldValuesLocalShare(
    const std::shared_ptr<yacl::link::Context>& ctx, int rank,
    const std::vector<uint64_t>& bit_shares,
    const std::vector<uint64_t>& receiver_values, const std::string& tag_prefix,
    const std::string& label) {
  const uint64_t my_n = static_cast<uint64_t>(bit_shares.size());
  const int peer = 1 - rank;
  if (rank == 1) {
    YACL_ENFORCE(bit_shares.size() == receiver_values.size(),
                 "receiver value size mismatch: {} vs {}", bit_shares.size(),
                 receiver_values.size());
  }

  if (rank == 0) {
    SendU64(ctx, peer, tag_prefix + "_n01", my_n);
    YACL_ENFORCE(RecvU64(ctx, peer, tag_prefix + "_n10") == my_n,
                 "Size mismatch");
  } else {
    SendU64(ctx, peer, tag_prefix + "_n10", my_n);
    YACL_ENFORCE(RecvU64(ctx, peer, tag_prefix + "_n01") == my_n,
                 "Size mismatch");
  }

  if (bit_shares.empty()) {
    return 0;
  }

  const size_t batch_items = std::max<size_t>(1, PjcBatchItemCount(my_n));
  const size_t batch_count = (bit_shares.size() + batch_items - 1) / batch_items;
  const size_t parallel_batches = PjcParallelBatchCount(batch_count);
  LogPjcStep(ctx, label + " schedule: batch_items=" +
                      std::to_string(batch_items) + ", batch_count=" +
                      std::to_string(batch_count) + ", parallel_batches=" +
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
      const size_t batch_n = std::min(batch_items, bit_shares.size() - offset);
      inflight[batch_idx] =
          std::async(std::launch::async,
                     [&, batch_idx, offset, batch_n]() -> uint64_t {
                       return SumReceiverHeldValuesBatchOt(
                           ctx, rank, bit_shares, receiver_values, offset,
                           batch_n, tag_prefix + "_B" + std::to_string(batch_idx),
                           label, batch_idx, batch_count);
                     });
    }

    total += inflight[completed++].get();
  }

  return total;
}

uint64_t MultiplySenderMaskByReceiverShare(
    const std::shared_ptr<yacl::link::Context>& ctx, int rank,
    uint64_t sender_mask, uint64_t receiver_share, const std::string& tag) {
  std::vector<uint64_t> sender_inputs(1, sender_mask);
  std::vector<uint64_t> receiver_inputs(1, receiver_share);
  const auto shares = MultiplySenderShareByReceiverValueOt(
      ctx, rank, sender_inputs, receiver_inputs, 0, 1, tag, 0, 1);
  YACL_ENFORCE(shares.size() == 1, "scalar product share size mismatch");
  return shares[0];
}

uint64_t RunPjcFromSenderState(const std::shared_ptr<yacl::link::Context>& ctx,
                               const std::vector<uint64_t>& equality_values,
                               const std::vector<uint64_t>& sender_offsets,
                               uint64_t global_mask,
                               const std::string& tag) {
  auto bit_shares = RunPeqtAndPackShares(ctx, equality_values, tag + "_PEQT");
  LogPjcStep(ctx, "enter product join sum, share_count=" +
                      std::to_string(bit_shares.size()));

  SendU64Vector(ctx, ctx->NextRank(), tag + "_OFFSETS", sender_offsets);

  const std::vector<uint64_t> empty_values;
  const uint64_t masked_sum_share = SumReceiverHeldValuesLocalShare(
      ctx, ctx->Rank(), bit_shares, empty_values, tag + "_MASKED_SUM",
      "masked product sum");
  const uint64_t y_sum_share = SumReceiverHeldValuesLocalShare(
      ctx, ctx->Rank(), bit_shares, empty_values, tag + "_Y_SUM", "weighted y sum");
  const uint64_t cross_share = MultiplySenderMaskByReceiverShare(
      ctx, ctx->Rank(), global_mask, 0, tag + "_MASK_CROSS");

  const uint64_t sender_total_share =
      masked_sum_share + global_mask * y_sum_share + cross_share;
  SendU64(ctx, ctx->NextRank(), tag + "_FINAL_REVEAL", sender_total_share);

  LogPjcStep(ctx, "leave product join sum");
  return 0;
}

uint64_t RunPjcFromDecodedValues(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& decoded_values,
    const std::vector<uint64_t>& receiver_plain_values, const std::string& tag) {
  auto bit_shares = ExtractHi64AndRunPeqt(ctx, decoded_values, tag + "_PEQT");
  auto receiver_value_shares = ExtractLow64(decoded_values);
  LogPjcStep(ctx, "enter product join sum, share_count=" +
                      std::to_string(bit_shares.size()));

  auto sender_offsets = RecvU64Vector(ctx, ctx->PrevRank(), tag + "_OFFSETS",
                                      receiver_value_shares.size());
  std::vector<uint64_t> masked_sender_values(receiver_value_shares.size(), 0);
  std::vector<uint64_t> masked_products(receiver_value_shares.size(), 0);
  yacl::parallel_for(
      0, receiver_value_shares.size(), [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          const size_t pos = static_cast<size_t>(idx);
          masked_sender_values[pos] =
              receiver_value_shares[pos] + sender_offsets[pos];
          masked_products[pos] =
              masked_sender_values[pos] * receiver_plain_values[pos];
        }
      });

  const uint64_t masked_sum_share = SumReceiverHeldValuesLocalShare(
      ctx, ctx->Rank(), bit_shares, masked_products, tag + "_MASKED_SUM",
      "masked product sum");
  const uint64_t y_sum_share = SumReceiverHeldValuesLocalShare(
      ctx, ctx->Rank(), bit_shares, receiver_plain_values, tag + "_Y_SUM",
      "weighted y sum");
  const uint64_t cross_share = MultiplySenderMaskByReceiverShare(
      ctx, ctx->Rank(), 0, y_sum_share, tag + "_MASK_CROSS");

  const uint64_t receiver_total =
      masked_sum_share + cross_share +
      RecvU64(ctx, ctx->PrevRank(), tag + "_FINAL_REVEAL");
  LogPjcStep(ctx, "leave product join sum");
  return receiver_total;
}

}  // namespace

uint64_t SHA2PjcSend(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av, okvs::Baxos baxos,
                     okvs::Baxos baxos2, uint32_t cuckoolen) {
  LogPjcStep(ctx, "step 1: sample r and build sender oracle table");
  uint128_t r = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      const size_t idx1 = static_cast<size_t>(idx) * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  const size_t okvssize = baxos.size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  const uint128_t suint = s.data()[0];

  LogPjcStep(ctx, "step 2: run base OT recv");
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  LogPjcStep(ctx, "step 3: derive sender masks");
  const size_t n = T_X.size();
  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  LogPjcStep(ctx, "step 4: wait receiver OKVS payload P");
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");
  std::memcpy(p.data(), buf.data(), buf.size());

  LogPjcStep(ctx, "step 5: wait omega_2 and decode first OKVS");
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  const uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(T_X), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> sender_offsets = RandVec<uint64_t>(cuckoolen);
  const uint64_t global_mask = yacl::crypto::FastRandU64();
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      const size_t idx1 = static_cast<size_t>(idx) * 3;
      const size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      const size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      const size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] =
          PackHiLo(rs[p1], items_av[idx] - (global_mask + sender_offsets[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] =
          PackHiLo(rs[p2], items_av[idx] - (global_mask + sender_offsets[p2])) ^
          sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] =
          PackHiLo(rs[p3], items_av[idx] - (global_mask + sender_offsets[p3])) ^
          sendermasks[idx1 + 2];
    }
  });

  std::vector<uint128_t> pp(baxos2.size());
  LogPjcStep(ctx, "step 6: encode second OKVS and send PP");
  baxos2.Solve(absl::MakeSpan(T_X), absl::MakeSpan(rsvalues),
               absl::MakeSpan(pp), nullptr, 8);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pp.data(), pp.size() * sizeof(uint128_t)),
      "Send PP");

  LogPjcStep(ctx, "step 7: start final PEQT + product sum");
  return RunPjcFromSenderState(ctx, rs, sender_offsets, global_mask,
                               "OTOKVS_PJC_SHA2_RR22");
}

uint64_t SHA2PjcRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av, okvs::Baxos baxos,
                     okvs::Baxos baxos2) {
  LogPjcStep(ctx, "step 1: wait sender seed r and build cuckoo table");
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  T_Y.Insert(elem_hashes);
  T_Y.Transform(r);
  auto receiver_plain_values = BuildReceiverSlotValues(T_Y, items_av);

  const size_t okvssize = baxos.size();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t_1"));

  LogPjcStep(ctx, "step 2: run base OT send");
  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  LogPjcStep(ctx, "step 3: encode receiver OKVS payload P");
  const size_t n = T_Y.bins_.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_A[idx], a_keys.data(), T_Y.bins_[idx]);
      sha256_encrypt_batch(all_B[idx], b_keys.data(), T_Y.bins_[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);
  baxos.Solve(absl::MakeSpan(T_Y.bins_), absl::MakeSpan(all_D),
              absl::MakeSpan(p), nullptr, 8);

  LogPjcStep(ctx, "step 4: send P and omega_2, then wait omega_1");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");
  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  YACL_ENFORCE(t1 == t_11, "t1 mismatch");
  const uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.size());
  LogPjcStep(ctx, "step 5: wait sender payload PP and decode second OKVS");
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");
  std::memcpy(pp.data(), buf.data(), buf.size());

  std::vector<uint128_t> decoded(T_Y.cuckoolen_);
  baxos2.Decode(absl::MakeSpan(T_Y.bins_), absl::MakeSpan(decoded),
                absl::MakeSpan(pp), 8);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      decoded[idx] ^= receivermasks[idx];
    }
  });

  LogPjcStep(ctx, "step 6: start final PEQT + product sum");
  return RunPjcFromDecodedValues(ctx, decoded, receiver_plain_values,
                                 "OTOKVS_PJC_SHA2_RR22");
}

uint64_t SHA2PjcSend(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av,
                     band_okvs::BandOkvs baxos,
                     band_okvs::BandOkvs baxos2, uint32_t cuckoolen) {
  LogPjcStep(ctx, "step 1: sample r and build sender oracle table");
  uint128_t r = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      const size_t idx1 = static_cast<size_t>(idx) * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  const size_t okvssize = baxos.Size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  const uint128_t suint = s.data()[0];

  LogPjcStep(ctx, "step 2: run base OT recv");
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  LogPjcStep(ctx, "step 3: derive sender masks");
  const size_t n = T_X.size();
  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  LogPjcStep(ctx, "step 4: wait receiver OKVS payload P");
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");
  std::memcpy(p.data(), buf.data(), buf.size());

  LogPjcStep(ctx, "step 5: wait omega_2 and decode first OKVS");
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  const uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(static_cast<int>(T_X.size()),
               reinterpret_cast<const oc::block*>(T_X.data()),
               reinterpret_cast<const oc::block*>(p.data()),
               reinterpret_cast<oc::block*>(sendermasks.data()));
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> sender_offsets = RandVec<uint64_t>(cuckoolen);
  const uint64_t global_mask = yacl::crypto::FastRandU64();
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      const size_t idx1 = static_cast<size_t>(idx) * 3;
      const size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      const size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      const size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] =
          PackHiLo(rs[p1], items_av[idx] - (global_mask + sender_offsets[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] =
          PackHiLo(rs[p2], items_av[idx] - (global_mask + sender_offsets[p2])) ^
          sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] =
          PackHiLo(rs[p3], items_av[idx] - (global_mask + sender_offsets[p3])) ^
          sendermasks[idx1 + 2];
    }
  });

  std::vector<uint128_t> pp(baxos2.Size());
  LogPjcStep(ctx, "step 6: encode second OKVS and send PP");
  baxos2.Encode(reinterpret_cast<const oc::block*>(T_X.data()),
                reinterpret_cast<const oc::block*>(rsvalues.data()),
                reinterpret_cast<oc::block*>(pp.data()));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pp.data(), pp.size() * sizeof(uint128_t)),
      "Send PP");

  LogPjcStep(ctx, "step 7: start final PEQT + product sum");
  return RunPjcFromSenderState(ctx, rs, sender_offsets, global_mask,
                               "OTOKVS_PJC_SHA2_BANDOKVS");
}

uint64_t SHA2PjcRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av,
                     band_okvs::BandOkvs baxos,
                     band_okvs::BandOkvs baxos2) {
  LogPjcStep(ctx, "step 1: wait sender seed r and build cuckoo table");
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  T_Y.Insert(elem_hashes);
  T_Y.Transform(r);
  auto receiver_plain_values = BuildReceiverSlotValues(T_Y, items_av);

  const size_t okvssize = baxos.Size();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t_1"));

  LogPjcStep(ctx, "step 2: run base OT send");
  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  LogPjcStep(ctx, "step 3: encode receiver OKVS payload P");
  const size_t n = T_Y.bins_.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_A[idx], a_keys.data(), T_Y.bins_[idx]);
      sha256_encrypt_batch(all_B[idx], b_keys.data(), T_Y.bins_[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);
  baxos.Encode(reinterpret_cast<const oc::block*>(T_Y.bins_.data()),
               reinterpret_cast<const oc::block*>(all_D.data()),
               reinterpret_cast<oc::block*>(p.data()));

  LogPjcStep(ctx, "step 4: send P and omega_2, then wait omega_1");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");
  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  YACL_ENFORCE(t1 == t_11, "t1 mismatch");
  const uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.Size());
  LogPjcStep(ctx, "step 5: wait sender payload PP and decode second OKVS");
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");
  std::memcpy(pp.data(), buf.data(), buf.size());

  std::vector<uint128_t> decoded(T_Y.cuckoolen_);
  baxos2.Decode(static_cast<int>(T_Y.bins_.size()),
                reinterpret_cast<const oc::block*>(T_Y.bins_.data()),
                reinterpret_cast<const oc::block*>(pp.data()),
                reinterpret_cast<oc::block*>(decoded.data()));
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      decoded[idx] ^= receivermasks[idx];
    }
  });

  LogPjcStep(ctx, "step 6: start final PEQT + product sum");
  return RunPjcFromDecodedValues(ctx, decoded, receiver_plain_values,
                                 "OTOKVS_PJC_SHA2_BANDOKVS");
}

}  // namespace pjc
