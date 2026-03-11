#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "examples/otokvspsi/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/link/context.h"

namespace pjc {

uint64_t SHA2PjcRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av,
                     okvs::Baxos baxos, okvs::Baxos baxos2);

uint64_t SHA2PjcSend(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av, okvs::Baxos baxos,
                     okvs::Baxos baxos2, uint32_t cuckoosize);

uint64_t SHA2PjcRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av,
                     band_okvs::BandOkvs baxos,
                     band_okvs::BandOkvs baxos2);

uint64_t SHA2PjcSend(const std::shared_ptr<yacl::link::Context>& ctx,
                     std::vector<uint128_t>& elem_hashes,
                     std::vector<uint64_t>& items_av,
                     band_okvs::BandOkvs baxos,
                     band_okvs::BandOkvs baxos2, uint32_t cuckoosize);

}  // namespace pjc
