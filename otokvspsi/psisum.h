#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "examples/otokvspsi/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/link/context.h"

namespace psisum {

uint64_t SHA2CPsiSumRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                         std::vector<uint128_t>& elem_hashes,
                         okvs::Baxos baxos, okvs::Baxos baxos2);

uint64_t SHA2CPsiSumSend(const std::shared_ptr<yacl::link::Context>& ctx,
                         std::vector<uint128_t>& elem_hashes,
                         okvs::Baxos baxos, okvs::Baxos baxos2,
                         uint32_t cuckoosize,
                         std::vector<uint64_t>& items_av);

uint64_t SHA2CPsiSumRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                         std::vector<uint128_t>& elem_hashes,
                         band_okvs::BandOkvs baxos,
                         band_okvs::BandOkvs baxos2);

uint64_t SHA2CPsiSumSend(const std::shared_ptr<yacl::link::Context>& ctx,
                         std::vector<uint128_t>& elem_hashes,
                         band_okvs::BandOkvs baxos,
                         band_okvs::BandOkvs baxos2, uint32_t cuckoosize,
                         std::vector<uint64_t>& items_av);

}  // namespace psisum
