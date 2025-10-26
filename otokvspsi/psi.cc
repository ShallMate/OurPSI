
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

namespace psi {

constexpr size_t KAPPA = 128;

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

inline void PackLowBits(const std::vector<uint128_t>& input,
                        std::vector<uint8_t>& out, size_t bytelen) {
  size_t n = input.size();
  out.resize(n * bytelen);
  for (size_t i = 0; i < n; ++i) {
    std::memcpy(&out[i * bytelen], &input[i], bytelen);
  }
}

inline void UnpackLowBits(const std::vector<uint8_t>& in,
                          std::vector<uint128_t>& output, size_t bytelen) {
  for (size_t i = 0; i < output.size(); ++i) {
    uint128_t val = 0;
    std::memcpy(&val, &in[i * bytelen], bytelen);
    output[i] = val;
  }
}

std::vector<bool> PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          size_t bytelen, size_t ns) {
  size_t okvssize = baxos.size();
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
  std::vector<uint128_t> receivermasks(n);
  uint128_t MASK = (static_cast<uint128_t>(1) << (bytelen * 8)) - 1;
  for (size_t idx = 0; idx < n; ++idx) {
    receivermasks[idx] = all_A[idx] & MASK;
  }
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  std::vector<uint8_t> sendermasks_bytes(ns * bytelen);

  std::memcpy(sendermasks_bytes.data(), buf.data(), buf.size());
  UnpackLowBits(sendermasks_bytes, sendermasks, bytelen);
  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);
  return z;
}

void PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
             size_t bytelen) {
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

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx];
    }
  });
  std::vector<uint8_t> sendermask_bytes;
  PackLowBits(sendermasks, sendermask_bytes, bytelen);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermask_bytes.data(),
                              sendermask_bytes.size() * sizeof(uint8_t)),
      "Sendermasks");
}

std::vector<bool> SHA2PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          size_t bytelen, size_t ns) {
  size_t okvssize = baxos.size();
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

  // === SHA2 ===

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
  std::vector<uint128_t> receivermasks(n);
  uint128_t MASK = (static_cast<uint128_t>(1) << (bytelen * 8)) - 1;
  for (size_t idx = 0; idx < n; ++idx) {
    receivermasks[idx] = all_A[idx] & MASK;
  }
  std::vector<uint128_t> sendermasks(ns);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  std::vector<uint8_t> sendermasks_bytes(ns * bytelen);

  std::memcpy(sendermasks_bytes.data(), buf.data(), buf.size());
  UnpackLowBits(sendermasks_bytes, sendermasks, bytelen);
  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);
  return z;
}

void SHA2PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
             size_t bytelen) {
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
      sha256_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx];
    }
  });
  std::vector<uint8_t> sendermask_bytes;
  PackLowBits(sendermasks, sendermask_bytes, bytelen);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermask_bytes.data(),
                              sendermask_bytes.size() * sizeof(uint8_t)),
      "Sendermasks");
}


std::vector<bool> PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          band_okvs::BandOkvs baxos, std::vector<bool>& mask,
                          size_t bytelen) {
  size_t okvssize = baxos.Size();

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
  std::vector<uint128_t> receivermasks(n);
  uint128_t MASK = (static_cast<uint128_t>(1) << (bytelen * 8)) - 1;
  for (size_t idx = 0; idx < n; ++idx) {
    receivermasks[idx] = all_A[idx] & MASK;
  }
  std::vector<uint128_t> sendermasks(n);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  std::vector<uint8_t> sendermasks_bytes(n * bytelen);

  std::memcpy(sendermasks_bytes.data(), buf.data(), buf.size());
  UnpackLowBits(sendermasks_bytes, sendermasks, bytelen);
  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);
  return z;

  return z;
}

void PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, band_okvs::BandOkvs baxos,
             size_t bytelen) {
  // Generate a random seed omega_1 for the first hash

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

  std::vector<uint128_t> sendermasks(n);

  baxos.Decode(reinterpret_cast<const oc::block*>(elem_hashes.data()),
               reinterpret_cast<const oc::block*>(p.data()),
               reinterpret_cast<oc::block*>(sendermasks.data()));

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx];
    }
  });
  std::vector<uint8_t> sendermask_bytes;
  PackLowBits(sendermasks, sendermask_bytes, bytelen);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermask_bytes.data(),
                              sendermask_bytes.size() * sizeof(uint8_t)),
      "Sendermasks");
}


std::vector<bool> PsiRecvSHA2(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          band_okvs::BandOkvs baxos, std::vector<bool>& mask,
                          size_t bytelen) {
  size_t okvssize = baxos.Size();

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
  std::vector<uint128_t> receivermasks(n);
  uint128_t MASK = (static_cast<uint128_t>(1) << (bytelen * 8)) - 1;
  for (size_t idx = 0; idx < n; ++idx) {
    receivermasks[idx] = all_A[idx] & MASK;
  }
  std::vector<uint128_t> sendermasks(n);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  std::vector<uint8_t> sendermasks_bytes(n * bytelen);

  std::memcpy(sendermasks_bytes.data(), buf.data(), buf.size());
  UnpackLowBits(sendermasks_bytes, sendermasks, bytelen);
  auto z = GetIntersectionMask(sendermasks, receivermasks, mask);
  return z;

  return z;
}

void PsiSendSHA2(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, band_okvs::BandOkvs baxos,
             size_t bytelen) {
  // Generate a random seed omega_1 for the first hash

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

  std::vector<uint128_t> sendermasks(n);

  baxos.Decode(reinterpret_cast<const oc::block*>(elem_hashes.data()),
               reinterpret_cast<const oc::block*>(p.data()),
               reinterpret_cast<oc::block*>(sendermasks.data()));

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx];
    }
  });
  std::vector<uint8_t> sendermask_bytes;
  PackLowBits(sendermasks, sendermask_bytes, bytelen);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermask_bytes.data(),
                              sendermask_bytes.size() * sizeof(uint8_t)),
      "Sendermasks");
}

}  // namespace psi