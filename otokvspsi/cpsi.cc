
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "examples/otokvspsi/bokvs.h"
#include "examples/otokvspsi/cuckoohash.h"
#include "examples/otokvspsi/okvs/baxos.h"
#include "examples/otokvspsi/utils.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

namespace cpsi {

constexpr size_t KAPPA = 128;

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<uint64_t> CPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               okvs::Baxos baxos, okvs::Baxos baxos2,
                               uint32_t cuckoolen,
                               std::vector<uint64_t>& items_av) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      size_t idx1 = idx * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  size_t okvssize = baxos.size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = T_X.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  // Receive omega_2
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(T_X), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> taus = RandVec<uint64_t>(cuckoolen);
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      size_t idx1 = idx * 3;
      size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] = ((static_cast<uint128_t>(rs[p1]) << 64) |
                        (items_av[idx] ^ taus[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] = ((static_cast<uint128_t>(rs[p2]) << 64) |
                            (items_av[idx] ^ taus[p2])) ^
                           sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] = ((static_cast<uint128_t>(rs[p3]) << 64) |
                            (items_av[idx] ^ taus[p3])) ^
                           sendermasks[idx1 + 2];
    }
  });

  std::vector<uint128_t> pp(baxos2.size());
  baxos2.Solve(absl::MakeSpan(T_X), absl::MakeSpan(rsvalues),
               absl::MakeSpan(pp), nullptr, 8);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pp.data(), pp.size() * sizeof(uint128_t)),
      "Send PP");

  return rs;
}

std::vector<uint64_t> CPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               okvs::Baxos baxos, okvs::Baxos baxos2) {
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  auto start_insert = std::chrono::high_resolution_clock::now();
  T_Y.Insert(elem_hashes);
  auto end_insert = std::chrono::high_resolution_clock::now();

  auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       end_insert - start_insert)
                       .count();
  std::cout << "Insert time: " << insert_ms << " ms" << std::endl;

  auto start_transform = std::chrono::high_resolution_clock::now();
  T_Y.Transform(r);
  auto end_transform = std::chrono::high_resolution_clock::now();

  auto transform_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          end_transform - start_transform)
                          .count();
  std::cout << "Transform time: " << transform_ms << " ms" << std::endl;

  size_t okvssize = baxos.size();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t1"));

  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = T_Y.bins_.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_A[idx], a_keys.data(), T_Y.bins_[idx]);
      aes128_encrypt_batch(all_B[idx], b_keys.data(), T_Y.bins_[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(T_Y.bins_), absl::MakeSpan(all_D),
              absl::MakeSpan(p), nullptr, 8);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");

  std::memcpy(pp.data(), buf.data(), buf.size());
  std::vector<uint128_t> rs(T_Y.cuckoolen_);
  baxos2.Decode(absl::MakeSpan(T_Y.bins_), absl::MakeSpan(rs),
                absl::MakeSpan(pp), 8);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rs[idx] = rs[idx] ^ receivermasks[idx];
    }
  });
  std::vector<uint64_t> rs_u64(rs.size());
  for (size_t i = 0; i < rs.size(); ++i) {
    rs_u64[i] = static_cast<uint64_t>(rs[i] >> 64);
  }
  return rs_u64;
}


std::vector<uint64_t> SHA2CPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               okvs::Baxos baxos, okvs::Baxos baxos2,
                               uint32_t cuckoolen,
                               std::vector<uint64_t>& items_av) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      size_t idx1 = idx * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  size_t okvssize = baxos.size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = T_X.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  // Receive omega_2
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(T_X), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> taus = RandVec<uint64_t>(cuckoolen);
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      size_t idx1 = idx * 3;
      size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] = ((static_cast<uint128_t>(rs[p1]) << 64) |
                        (items_av[idx] ^ taus[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] = ((static_cast<uint128_t>(rs[p2]) << 64) |
                            (items_av[idx] ^ taus[p2])) ^
                           sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] = ((static_cast<uint128_t>(rs[p3]) << 64) |
                            (items_av[idx] ^ taus[p3])) ^
                           sendermasks[idx1 + 2];
    }
  });

  std::vector<uint128_t> pp(baxos2.size());
  baxos2.Solve(absl::MakeSpan(T_X), absl::MakeSpan(rsvalues),
               absl::MakeSpan(pp), nullptr, 8);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pp.data(), pp.size() * sizeof(uint128_t)),
      "Send PP");

  return rs;
}

std::vector<uint64_t> SHA2CPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               okvs::Baxos baxos, okvs::Baxos baxos2) {
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  auto start_insert = std::chrono::high_resolution_clock::now();
  T_Y.Insert(elem_hashes);
  auto end_insert = std::chrono::high_resolution_clock::now();

  auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       end_insert - start_insert)
                       .count();
  std::cout << "Insert time: " << insert_ms << " ms" << std::endl;

  auto start_transform = std::chrono::high_resolution_clock::now();
  T_Y.Transform(r);
  auto end_transform = std::chrono::high_resolution_clock::now();

  auto transform_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          end_transform - start_transform)
                          .count();
  std::cout << "Transform time: " << transform_ms << " ms" << std::endl;

  size_t okvssize = baxos.size();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t1"));

  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === SHA2 Encryption ===

  size_t n = T_Y.bins_.size();
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

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");

  std::memcpy(pp.data(), buf.data(), buf.size());
  std::vector<uint128_t> rs(T_Y.cuckoolen_);
  baxos2.Decode(absl::MakeSpan(T_Y.bins_), absl::MakeSpan(rs),
                absl::MakeSpan(pp), 8);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rs[idx] = rs[idx] ^ receivermasks[idx];
    }
  });
  std::vector<uint64_t> rs_u64(rs.size());
  for (size_t i = 0; i < rs.size(); ++i) {
    rs_u64[i] = static_cast<uint64_t>(rs[i] >> 64);
  }
  return rs_u64;
}


std::vector<uint64_t> CPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               band_okvs::BandOkvs baxos,
                               band_okvs::BandOkvs baxos2, uint32_t cuckoolen,
                               std::vector<uint64_t>& items_av) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      size_t idx1 = idx * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  size_t okvssize = baxos.Size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = T_X.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  // Receive omega_2
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);

  baxos.Decode(reinterpret_cast<const oc::block*>(T_X.data()),
               reinterpret_cast<const oc::block*>(p.data()),
               reinterpret_cast<oc::block*>(sendermasks.data()));
  cout << "this1" << endl;

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> taus = RandVec<uint64_t>(cuckoolen);
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      size_t idx1 = idx * 3;
      size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] = ((static_cast<uint128_t>(rs[p1]) << 64) |
                        (items_av[idx] ^ taus[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] = ((static_cast<uint128_t>(rs[p2]) << 64) |
                            (items_av[idx] ^ taus[p2])) ^
                           sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] = ((static_cast<uint128_t>(rs[p3]) << 64) |
                            (items_av[idx] ^ taus[p3])) ^
                           sendermasks[idx1 + 2];
    }
  });

  std::vector<uint128_t> pp(baxos2.Size());
  baxos2.Encode(reinterpret_cast<const oc::block*>(T_X.data()),
                reinterpret_cast<const oc::block*>(rsvalues.data()),
                reinterpret_cast<oc::block*>(pp.data()));
  cout << "this3" << endl;
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pp.data(), pp.size() * sizeof(uint128_t)),
      "Send PP");

  return rs;
}

std::vector<uint64_t> CPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               band_okvs::BandOkvs baxos,
                               band_okvs::BandOkvs baxos2) {
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  auto start_insert = std::chrono::high_resolution_clock::now();
  T_Y.Insert(elem_hashes);
  auto end_insert = std::chrono::high_resolution_clock::now();

  auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       end_insert - start_insert)
                       .count();
  std::cout << "Insert time: " << insert_ms << " ms" << std::endl;

  auto start_transform = std::chrono::high_resolution_clock::now();
  T_Y.Transform(r);
  auto end_transform = std::chrono::high_resolution_clock::now();

  auto transform_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          end_transform - start_transform)
                          .count();
  std::cout << "Transform time: " << transform_ms << " ms" << std::endl;

  size_t okvssize = baxos.Size();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t1"));

  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = T_Y.bins_.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_A[idx], a_keys.data(), T_Y.bins_[idx]);
      aes128_encrypt_batch(all_B[idx], b_keys.data(), T_Y.bins_[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Encode(reinterpret_cast<const oc::block*>(T_Y.bins_.data()),
               reinterpret_cast<const oc::block*>(all_D.data()),
               reinterpret_cast<oc::block*>(p.data()));

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.Size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");

  std::memcpy(pp.data(), buf.data(), buf.size());
  std::vector<uint128_t> rs(T_Y.cuckoolen_);
  baxos2.Decode(reinterpret_cast<const oc::block*>(T_Y.bins_.data()),
                reinterpret_cast<const oc::block*>(pp.data()),
                reinterpret_cast<oc::block*>(rs.data()));
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rs[idx] = rs[idx] ^ receivermasks[idx];
    }
  });
  std::vector<uint64_t> rs_u64(rs.size());
  for (size_t i = 0; i < rs.size(); ++i) {
    rs_u64[i] = static_cast<uint64_t>(rs[i] >> 64);
  }
  return rs_u64;
}

std::vector<uint64_t> CPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               OKVSBK baxos, OKVSBK baxos2, uint32_t cuckoolen,
                               std::vector<uint64_t>& items_av) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      size_t idx1 = idx * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  size_t okvssize = baxos.getM();
  // cout<<"okvssize: "<<okvssize<<endl;
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = T_X.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  // Receive omega_2
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);

  baxos.DecodeOtherP(T_X, sendermasks, p);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });
  // cout<<"this2"<<endl;

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> taus = RandVec<uint64_t>(cuckoolen);
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      size_t idx1 = idx * 3;
      size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] = ((static_cast<uint128_t>(rs[p1]) << 64) |
                        (items_av[idx] ^ taus[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] = ((static_cast<uint128_t>(rs[p2]) << 64) |
                            (items_av[idx] ^ taus[p2])) ^
                           sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] = ((static_cast<uint128_t>(rs[p3]) << 64) |
                            (items_av[idx] ^ taus[p3])) ^
                           sendermasks[idx1 + 2];
    }
  });
  baxos2.Encode(T_X, rsvalues);
  // cout<<"this3"<<endl;
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(baxos2.p_.data(),
                                         baxos2.p_.size() * sizeof(uint128_t)),
                 "Send PP");
  return rs;
}

std::vector<uint64_t> CPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               OKVSBK baxos, OKVSBK baxos2) {
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  // auto start_insert = std::chrono::high_resolution_clock::now();
  T_Y.Insert(elem_hashes);
  // auto end_insert = std::chrono::high_resolution_clock::now();

  // auto insert_ms =
  // std::chrono::duration_cast<std::chrono::milliseconds>(end_insert -
  // start_insert).count(); std::cout << "Insert time: " << insert_ms << " ms"
  // << std::endl;

  // auto start_transform = std::chrono::high_resolution_clock::now();
  T_Y.Transform(r);
  // auto end_transform = std::chrono::high_resolution_clock::now();

  // auto transform_ms =
  // std::chrono::duration_cast<std::chrono::milliseconds>(end_transform -
  // start_transform).count(); std::cout << "Transform time: " << transform_ms
  // << " ms" << std::endl;

  size_t okvssize = baxos.getM();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t1"));

  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = T_Y.bins_.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_A[idx], a_keys.data(), T_Y.bins_[idx]);
      aes128_encrypt_batch(all_B[idx], b_keys.data(), T_Y.bins_[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Encode(T_Y.bins_, all_D);
  // cout<<"this1"<<endl;

  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(baxos.p_.data(),
                                         baxos.p_.size() * sizeof(uint128_t)),
                 "Send P");

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.getM());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");

  std::memcpy(pp.data(), buf.data(), buf.size());
  // cout<<"this4"<<endl;
  std::vector<uint128_t> rs(T_Y.cuckoolen_);
  baxos2.DecodeDifflenP(T_Y.bins_, rs, pp);
  // cout<<"this5"<<endl;
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rs[idx] = rs[idx] ^ receivermasks[idx];
    }
  });
  std::vector<uint64_t> rs_u64(rs.size());
  for (size_t i = 0; i < rs.size(); ++i) {
    rs_u64[i] = static_cast<uint64_t>(rs[i] >> 64);
  }
  return rs_u64;
}


std::vector<uint64_t> SHA2CPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               OKVSBK baxos, OKVSBK baxos2, uint32_t cuckoolen,
                               std::vector<uint64_t>& items_av) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");

  std::vector<uint128_t> T_X(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i y_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      size_t idx1 = idx * 3;
      T_X[idx1] = Oracle(1, key_block, y_block);
      T_X[idx1 + 1] = Oracle(2, key_block, y_block);
      T_X[idx1 + 2] = Oracle(3, key_block, y_block);
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  size_t okvssize = baxos.getM();
  // cout<<"okvssize: "<<okvssize<<endl;
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = T_X.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_C[idx], c_keys.data(), T_X[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  // Receive omega_2
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);

  baxos.DecodeOtherP(T_X, sendermasks, p);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });
  // cout<<"this2"<<endl;

  std::vector<uint64_t> rs = RandVec<uint64_t>(cuckoolen);
  std::vector<uint64_t> taus = RandVec<uint64_t>(cuckoolen);
  std::vector<uint128_t> rsvalues(n);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      size_t idx1 = idx * 3;
      size_t p1 = GetHash(1, elem_hashes[idx]) % cuckoolen;
      size_t p2 = GetHash(2, elem_hashes[idx]) % cuckoolen;
      size_t p3 = GetHash(3, elem_hashes[idx]) % cuckoolen;
      rsvalues[idx1] = ((static_cast<uint128_t>(rs[p1]) << 64) |
                        (items_av[idx] ^ taus[p1])) ^
                       sendermasks[idx1];
      rsvalues[idx1 + 1] = ((static_cast<uint128_t>(rs[p2]) << 64) |
                            (items_av[idx] ^ taus[p2])) ^
                           sendermasks[idx1 + 1];
      rsvalues[idx1 + 2] = ((static_cast<uint128_t>(rs[p3]) << 64) |
                            (items_av[idx] ^ taus[p3])) ^
                           sendermasks[idx1 + 2];
    }
  });
  baxos2.Encode(T_X, rsvalues);
  // cout<<"this3"<<endl;
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(baxos2.p_.data(),
                                         baxos2.p_.size() * sizeof(uint128_t)),
                 "Send PP");
  return rs;
}

std::vector<uint64_t> SHA2CPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               OKVSBK baxos, OKVSBK baxos2) {
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  CuckooHash T_Y(elem_hashes.size());
  // auto start_insert = std::chrono::high_resolution_clock::now();
  T_Y.Insert(elem_hashes);
  // auto end_insert = std::chrono::high_resolution_clock::now();

  // auto insert_ms =
  // std::chrono::duration_cast<std::chrono::milliseconds>(end_insert -
  // start_insert).count(); std::cout << "Insert time: " << insert_ms << " ms"
  // << std::endl;

  // auto start_transform = std::chrono::high_resolution_clock::now();
  T_Y.Transform(r);
  // auto end_transform = std::chrono::high_resolution_clock::now();

  // auto transform_ms =
  // std::chrono::duration_cast<std::chrono::milliseconds>(end_transform -
  // start_transform).count(); std::cout << "Transform time: " << transform_ms
  // << " ms" << std::endl;

  size_t okvssize = baxos.getM();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t1"));

  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = T_Y.bins_.size();
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

  baxos.Encode(T_Y.bins_, all_D);
  // cout<<"this1"<<endl;

  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(baxos.p_.data(),
                                         baxos.p_.size() * sizeof(uint128_t)),
                 "Send P");

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });

  std::vector<uint128_t> pp(baxos2.getM());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");

  std::memcpy(pp.data(), buf.data(), buf.size());
  // cout<<"this4"<<endl;
  std::vector<uint128_t> rs(T_Y.cuckoolen_);
  baxos2.DecodeDifflenP(T_Y.bins_, rs, pp);
  // cout<<"this5"<<endl;
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rs[idx] = rs[idx] ^ receivermasks[idx];
    }
  });
  std::vector<uint64_t> rs_u64(rs.size());
  for (size_t i = 0; i < rs.size(); ++i) {
    rs_u64[i] = static_cast<uint64_t>(rs[i] >> 64);
  }
  return rs_u64;
}


}  // namespace cpsi
