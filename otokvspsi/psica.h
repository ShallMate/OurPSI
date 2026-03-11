#pragma once

#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "examples/otokvspsi/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"

namespace psica {

uint64_t CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                    okvs::Baxos baxos2);

uint64_t CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                    okvs::Baxos baxos2, uint32_t cuckoosize,
                    std::vector<uint64_t>& items_av);

uint64_t SHA2CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                        okvs::Baxos baxos2);

uint64_t SHA2CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                        okvs::Baxos baxos2, uint32_t cuckoosize,
                        std::vector<uint64_t>& items_av);

uint64_t CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes,
                    band_okvs::BandOkvs baxos,
                    band_okvs::BandOkvs baxos2);

uint64_t CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                    std::vector<uint128_t>& elem_hashes,
                    band_okvs::BandOkvs baxos,
                    band_okvs::BandOkvs baxos2, uint32_t cuckoosize,
                    std::vector<uint64_t>& items_av);

uint64_t SHA2CPsiCaRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes,
                        band_okvs::BandOkvs baxos,
                        band_okvs::BandOkvs baxos2);

uint64_t SHA2CPsiCaSend(const std::shared_ptr<yacl::link::Context>& ctx,
                        std::vector<uint128_t>& elem_hashes,
                        band_okvs::BandOkvs baxos,
                        band_okvs::BandOkvs baxos2, uint32_t cuckoosize,
                        std::vector<uint64_t>& items_av);

}  // namespace psica
