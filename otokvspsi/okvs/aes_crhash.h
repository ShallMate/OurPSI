

#pragma once

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

// Correlation robust hash function.
// H(x) = AES(x) + x.
namespace okvs {

class AesCrHash : public yacl::crypto::SymmetricCrypto {
 public:
  explicit AesCrHash(uint128_t key, uint128_t iv = 0)
      : yacl::crypto::SymmetricCrypto(
            yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB, key, iv) {}

  AesCrHash(yacl::ByteContainerView key, yacl::ByteContainerView iv)
      : yacl::crypto::SymmetricCrypto(
            yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB, key, iv) {}

  void Hash(absl::Span<const uint8_t> plaintext,
            absl::Span<uint8_t> ciphertext) const;

  void Hash(absl::Span<const uint128_t> plaintext,
            absl::Span<uint128_t> ciphertext) const;

  uint128_t Hash(uint128_t input) const;
};

}  // namespace okvs
