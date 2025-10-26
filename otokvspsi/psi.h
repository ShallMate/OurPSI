#pragma once

#include <cstddef>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "examples/otokvspsi/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"

namespace psi {

extern size_t KAPPA;

std::vector<bool> PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          size_t bytelen, size_t ns);

void PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
             size_t bytelen);


std::vector<bool> SHA2PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos, std::vector<bool>& mask,
                          size_t bytelen, size_t ns);

void SHA2PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
             size_t bytelen);

std::vector<bool> PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          band_okvs::BandOkvs baxos, std::vector<bool>& mask,
                          size_t bytelen);

void PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, band_okvs::BandOkvs baxos,
             size_t bytelen);


std::vector<bool> SHA2PsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          band_okvs::BandOkvs baxos, std::vector<bool>& mask,
                          size_t bytelen);

void SHA2PsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, band_okvs::BandOkvs baxos,
             size_t bytelen);

}  // namespace psi