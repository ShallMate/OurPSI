
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
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

namespace malpsi {

constexpr size_t KAPPA = 128;

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<bool> PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          uint64_t ns) {
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

  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_A[idx], a_keys.data(), elem_hashes[idx]);
      aes128_encrypt_batch(all_B[idx], b_keys.data(), elem_hashes[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(all_D),
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
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");

  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);

  return z;
}

void PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos) {
  // Generate a random seed omega_1 for the first hash
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
  size_t n = elem_hashes.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
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
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Sendermasks");
}

std::vector<bool> PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          band_okvs::BandOkvs baxos, std::vector<bool>& mask,
                          uint64_t ns) {
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

  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_A[idx], a_keys.data(), elem_hashes[idx]);
      aes128_encrypt_batch(all_B[idx], b_keys.data(), elem_hashes[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Encode(reinterpret_cast<const oc::block*>(elem_hashes.data()),
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
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");

  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);

  return z;
}

void PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, band_okvs::BandOkvs baxos) {
  // Generate a random seed omega_1 for the first hash
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
  size_t n = elem_hashes.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
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
  // std::cout << "this" << std::endl;
  baxos.Decode(reinterpret_cast<const oc::block*>(elem_hashes.data()),
               reinterpret_cast<const oc::block*>(p.data()),
               reinterpret_cast<oc::block*>(sendermasks.data()));
  // std::cout << "this" << std::endl;

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Sendermasks");
}


std::vector<bool> Blake3PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          uint64_t ns) {
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

  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      blake3_encrypt_batch(all_A[idx], a_keys.data(), elem_hashes[idx]);
      blake3_encrypt_batch(all_B[idx], b_keys.data(), elem_hashes[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(all_D),
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
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");

  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);

  return z;
}

void Blake3PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos) {
  // Generate a random seed omega_1 for the first hash
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
  size_t n = elem_hashes.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      blake3_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
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
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Sendermasks");
}

std::vector<bool> SHA2PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          uint64_t ns) {
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

  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_A[idx], a_keys.data(), elem_hashes[idx]);
      sha256_encrypt_batch(all_B[idx], b_keys.data(), elem_hashes[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(all_D),
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
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");

  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);

  return z;
}

void SHA2PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos) {
  // Generate a random seed omega_1 for the first hash
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

  // === SHA2 Encrypt ===
  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
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
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Sendermasks");
}





std::vector<bool> SHA2PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          band_okvs::BandOkvs baxos, std::vector<bool>& mask,
                          uint64_t ns) {
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

  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_A[idx], a_keys.data(), elem_hashes[idx]);
      sha256_encrypt_batch(all_B[idx], b_keys.data(), elem_hashes[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Encode(reinterpret_cast<const oc::block*>(elem_hashes.data()),
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
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");

  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);

  return z;
}

void SHA2PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, band_okvs::BandOkvs baxos) {
  // Generate a random seed omega_1 for the first hash
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

  // === SHA2 Encrypt ===
  size_t n = elem_hashes.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sha256_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
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
  // std::cout << "this" << std::endl;
  baxos.Decode(reinterpret_cast<const oc::block*>(elem_hashes.data()),
               reinterpret_cast<const oc::block*>(p.data()),
               reinterpret_cast<oc::block*>(sendermasks.data()));
  // std::cout << "this" << std::endl;

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx] ^ omega;
    }
  });

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Sendermasks");
}

}  // namespace malpsi
