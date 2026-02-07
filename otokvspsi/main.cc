#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>

#include "examples/otokvspsi/bandokvs/band_okvs.h"
#include "examples/otokvspsi/bandokvs/utils.h"
#include "examples/otokvspsi/cpsi.h"
#include "examples/otokvspsi/malpsi.h"
#include "examples/otokvspsi/okvs/baxos.h"
#include "examples/otokvspsi/psi.h"
#include "examples/otokvspsi/utils.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;
using namespace band_okvs;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

void OurPSIRR22(size_t logns = 24, size_t lognr = 24) {

  const uint64_t ns = 1<<logns;
  const uint64_t nr = 1<<lognr;
  size_t bin_size = nr / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  std::cout <<"=================Test Our PSI in malicious model with RR22=================T" <<std::endl;
  std::cout <<"Random Oracle: AES128" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(nr, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(
      std::launch::async, [&] { malpsi::PsiSend(lctxs[0], items_a, baxos); });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return malpsi::PsiRecv(lctxs[1], items_b, baxos, intersection_mask, ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}


void OurPSIRR22SHA2(size_t logns = 24, size_t lognr = 24) {
  const uint64_t ns = 1 << logns;
  const uint64_t nr = 1 << lognr;
  size_t bin_size = nr / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  std::cout <<"=================Test Our PSI in malicious model with RR22=================" <<std::endl;
  std::cout <<"Random Oracle: SHA2" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(nr, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(1200000);
  lctxs[1]->SetRecvTimeout(1200000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(
      std::launch::async, [&] { malpsi::SHA2PsiSend(lctxs[0], items_a, baxos); });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return malpsi::SHA2PsiRecv(lctxs[1], items_b, baxos, intersection_mask, ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}


void OurPSIRR22Blake3() {
  const uint64_t ns = 1 << 20;
  const uint64_t nr = 1 << 20;
  size_t bin_size = nr / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(nr, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(
      std::launch::async, [&] { malpsi::Blake3PsiSend(lctxs[0], items_a, baxos); });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return malpsi::Blake3PsiRecv(lctxs[1], items_b, baxos, intersection_mask, ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurSemiPSIRR22() {
  size_t logns = 20;
  size_t lognr = 20;
  uint64_t ns = 1 << logns;
  uint64_t nr = 1 << lognr;
  size_t bin_size = nr / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  size_t bytelen = ((40 + logns + lognr + 7) / 8);
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  std::cout <<"=================Test Our PSI in semi-honest model with RR22=================" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(nr, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    psi::PsiSend(lctxs[0], items_a, baxos, bytelen);
  });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return psi::PsiRecv(lctxs[1], items_b, baxos, intersection_mask, bytelen,
                        ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurSemiPSIRR22SHA2(size_t logns = 24, size_t lognr = 24) {
  uint64_t ns = 1 << logns;
  uint64_t nr = 1 << lognr;
  size_t bin_size = nr / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  size_t bytelen = ((40 + logns + lognr + 7) / 8);
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  std::cout <<"=================Test Our PSI in semi-honest model with RR22=================" <<std::endl;
  std::cout <<"Random Oracle: SHA2" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(nr, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    psi::SHA2PsiSend(lctxs[0], items_a, baxos, bytelen);
  });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return psi::SHA2PsiRecv(lctxs[1], items_b, baxos, intersection_mask, bytelen,
                        ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}


void OurSemiPSIBPSY() {
  double epsilon = 0.03;
  size_t logn = 20;
  int n = 1 << logn;
  int m = static_cast<int>((1 + epsilon) * n);
  cout << "OKVS len: " << m << endl;
  int band_length = 240;
  size_t bytelen = ((40 + 2 * logn + 7) / 8);
  std::random_device rd;
  std::uniform_int_distribution<uint64_t> dist;
  std::cout <<"=================Test Our PSI in semi-honest model with BPSY23=================" <<std::endl;
  std::cout <<"Sender size: " << n << ", Receiver size: " << n << std::endl;

  oc::PRNG prng(oc::block(dist(rd), dist(rd)));

  BandOkvs okvs;
  okvs.Init(n, m, band_length, oc::block(dist(rd), dist(rd)));
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(0, n);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    psi::PsiSend(lctxs[0], items_a, okvs, bytelen);
  });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return psi::PsiRecv(lctxs[1], items_b, okvs, intersection_mask, bytelen);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurSemiPSIBPSYSHA2(size_t logn = 24) {
  double epsilon = 0.03;
  int n = 1 << logn;
  int m = static_cast<int>((1 + epsilon) * n);
  cout << "OKVS len: " << m << endl;
  int band_length = 240;
  size_t bytelen = ((40 + 2 * logn + 7) / 8);
  std::random_device rd;
  std::uniform_int_distribution<uint64_t> dist;
  std::cout <<"=================Test Our PSI in semi-honest model with BPSY23=================" <<std::endl;
  std::cout <<"Random Oracle: SHA2" <<std::endl;
  std::cout <<"Sender size: " << n << ", Receiver size: " << n << std::endl;

  oc::PRNG prng(oc::block(dist(rd), dist(rd)));

  BandOkvs okvs;
  okvs.Init(n, m, band_length, oc::block(dist(rd), dist(rd)));
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(0, n);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    psi::PsiSend(lctxs[0], items_a, okvs, bytelen);
  });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return psi::PsiRecv(lctxs[1], items_b, okvs, intersection_mask, bytelen);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}


void OurPSIBPSY(size_t logns = 24, size_t lognr = 24) {
  double epsilon = 0.03;
  size_t ns = 1 << logns;
  size_t nr = 1 << lognr;
  int m = static_cast<int>((1 + epsilon) * nr);
  cout << "OKVS len: " << m << endl;
  int band_length = 240;
  std::cout <<"=================Test Our PSI in malicious model with BPSY23=================" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;
  std::random_device rd;
  std::uniform_int_distribution<uint64_t> dist;

  oc::PRNG prng(oc::block(dist(rd), dist(rd)));

  BandOkvs okvs;
  okvs.Init(nr, m, band_length, oc::block(dist(rd), dist(rd)));
  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(
      std::launch::async, [&] { malpsi::PsiSend(lctxs[0], items_a, okvs); });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return malpsi::PsiRecv(lctxs[1], items_b, okvs, intersection_mask, ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurPSIBPSYSHA2(size_t logns = 24, size_t lognr = 24) {
  double epsilon = 0.03;
  size_t ns = 1 << logns;
  size_t nr = 1 << lognr;
  int m = static_cast<int>((1 + epsilon) * nr);
  cout << "OKVS len: " << m << endl;
  int band_length = 240;
  std::cout <<"=================Test Our PSI in malicious model with BPSY23=================" <<std::endl;
  std::cout <<"Random Oracle: SHA2" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;
  std::random_device rd;
  std::uniform_int_distribution<uint64_t> dist;

  oc::PRNG prng(oc::block(dist(rd), dist(rd)));

  BandOkvs okvs;
  okvs.Init(nr, m, band_length, oc::block(dist(rd), dist(rd)));
  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(
      std::launch::async, [&] { malpsi::SHA2PsiSend(lctxs[0], items_a, okvs); });

  std::future<std::vector<bool>> receiver = std::async(std::launch::async, [&] {
    return malpsi::SHA2PsiRecv(lctxs[1], items_b, okvs, intersection_mask, ns);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurCPSIRR22() {
  const uint64_t ns = 1 << 20;
  const uint64_t nr = 1 << 20;
  size_t cuckoolen = static_cast<uint32_t>(nr * 1.27);
  size_t bin_size = cuckoolen / 4;
  size_t weight = 3;
  size_t ssp = 40;

  okvs::Baxos baxos;
  okvs::Baxos baxos2;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  std::cout <<"=================Test Our Circult PSI with RR22=================" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(cuckoolen, bin_size, weight, ssp,
             okvs::PaxosParam::DenseType::GF128, seed);
  baxos2.Init(ns * 3, bin_size * 3, weight, ssp,
              okvs::PaxosParam::DenseType::GF128, seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint64_t> items_av = RandVec<uint64_t>(ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<uint64_t> items_bv = RandVec<uint64_t>(nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<uint64_t>> sender =
      std::async(std::launch::async, [&] {
        return cpsi::CPsiSend(lctxs[0], items_a, baxos, baxos2, cuckoolen,
                              items_av);
      });

  std::future<std::vector<uint64_t>> receiver = std::async(
      std::launch::async,
      [&] { return cpsi::CPsiRecv(lctxs[1], items_b, baxos, baxos2); });

  auto rs = sender.get();
  auto rr = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  size_t match_count = 0;
  size_t min_len = std::min(rs.size(), rr.size());

  for (size_t i = 0; i < min_len; ++i) {
    if (rs[i] == rr[i]) {
      ++match_count;
    }
  }

  std::cout << "result number: " << match_count << std::endl;

  // size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  // std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  // std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurCPSIRR22SHA2(size_t logns = 24, size_t lognr = 24) {
  const uint64_t ns = 1 << logns;
  const uint64_t nr = 1 << lognr;
  size_t cuckoolen = static_cast<uint32_t>(nr * 1.27);
  size_t bin_size = cuckoolen / 4;
  size_t weight = 3;
  size_t ssp = 40;

  okvs::Baxos baxos;
  okvs::Baxos baxos2;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  std::cout <<"=================Test Our Circult PSI with RR22=================" <<std::endl;
  std::cout <<"Random Oracle: SHA2" <<std::endl;
  std::cout <<"Sender size: " << ns << ", Receiver size: " << nr << std::endl;

  SPDLOG_INFO("items_num:{}, bin_size:{}", nr, bin_size);

  baxos.Init(cuckoolen, bin_size, weight, ssp,
             okvs::PaxosParam::DenseType::GF128, seed);
  baxos2.Init(ns * 3, bin_size * 3, weight, ssp,
              okvs::PaxosParam::DenseType::GF128, seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint64_t> items_av = RandVec<uint64_t>(ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);
  std::vector<uint64_t> items_bv = RandVec<uint64_t>(nr);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<uint64_t>> sender =
      std::async(std::launch::async, [&] {
        return cpsi::SHA2CPsiSend(lctxs[0], items_a, baxos, baxos2, cuckoolen,
                              items_av);
      });

  std::future<std::vector<uint64_t>> receiver = std::async(
      std::launch::async,
      [&] { return cpsi::SHA2CPsiRecv(lctxs[1], items_b, baxos, baxos2); });

  auto rs = sender.get();
  auto rr = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  size_t match_count = 0;
  size_t min_len = std::min(rs.size(), rr.size());

  for (size_t i = 0; i < min_len; ++i) {
    if (rs[i] == rr[i]) {
      ++match_count;
    }
  }

  std::cout << "result number: " << match_count << std::endl;

  // size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  // std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  // std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void OurCPSIBPSY() {
  size_t num = 1 << 20;
  size_t w = 360;
  double e = 1.03;
  size_t cuckoolen = static_cast<uint32_t>(num * 1.27);
  // cout << "Cuckoo len: " << cuckoolen << std::endl;
  OKVSBK baxos(cuckoolen, w, e);
  // cout << "OKVS len: " << baxos.getM() << std::endl;
  OKVSBK baxos2(num * 3, w, e);
  // int m = static_cast<int>((1 + e) * cuckoolen);
  std::vector<uint128_t> items_a = CreateRangeItems(0, num);
  std::vector<uint64_t> items_av = RandVec<uint64_t>(num);
  std::vector<uint128_t> items_b = CreateRangeItems(0, num);
  std::vector<uint64_t> items_bv = RandVec<uint64_t>(num);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);
  std::cout <<"=================Test Our Circult PSI with BPSY23=================" <<std::endl;
  std::cout <<"Random Oracle: AES-128" <<std::endl;
  std::cout <<"Sender size: " << num << ", Receiver size: " << num << std::endl;


  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<uint64_t>> sender =
      std::async(std::launch::async, [&] {
        return cpsi::CPsiSend(lctxs[0], items_a, baxos, baxos2, cuckoolen,
                              items_av);
      });

  std::future<std::vector<uint64_t>> receiver = std::async(
      std::launch::async,
      [&] { return cpsi::CPsiRecv(lctxs[1], items_b, baxos, baxos2); });

  auto rs = sender.get();
  auto rr = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  // size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  // std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  // std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}


void OurCPSIBPSYSHA2(size_t logn = 24) {
  size_t num = 1 << logn;
  size_t w = 180;
  double e = 1.03;
  size_t cuckoolen = static_cast<uint32_t>(num * 1.27);
  // cout << "Cuckoo len: " << cuckoolen << std::endl;
  OKVSBK baxos(cuckoolen, w, e);
  // cout << "OKVS len: " << baxos.getM() << std::endl;
  OKVSBK baxos2(num * 3, w, e);
  // int m = static_cast<int>((1 + e) * cuckoolen);
  std::vector<uint128_t> items_a = CreateRangeItems(0, num);
  std::vector<uint64_t> items_av = RandVec<uint64_t>(num);
  std::vector<uint128_t> items_b = CreateRangeItems(0, num);
  std::vector<uint64_t> items_bv = RandVec<uint64_t>(num);
  std::vector<bool> intersection_mask;
  intersection_mask.assign(items_b.size(), false);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);
  std::cout <<"=================Test Our Circult PSI with BPSY23=================" <<std::endl;
  std::cout <<"Random Oracle: SHA2" <<std::endl;
  std::cout <<"Sender size: " << num << ", Receiver size: " << num << std::endl;


  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<uint64_t>> sender =
      std::async(std::launch::async, [&] {
        return cpsi::CPsiSend(lctxs[0], items_a, baxos, baxos2, cuckoolen,
                              items_av);
      });

  std::future<std::vector<uint64_t>> receiver = std::async(
      std::launch::async,
      [&] { return cpsi::CPsiRecv(lctxs[1], items_b, baxos, baxos2); });

  auto rs = sender.get();
  auto rr = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  // size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  // std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  // std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

enum class Mode { PSI, CPSI };
enum class OKVS { RR22, BPSY23 };
enum class Oracle {SHA, AES};


static void print_usage(const char* prog) {
  cerr <<
    "Usage (numeric shorthand):\n"
    "  " << prog << " <0|1> <0|1> [size logs...]\n"
    "    arg1: 0=PSI, 1=CPSI (including PSI-CA, PSI-sum, and PJC)\n"
    "    arg2: 0=RR22, 1=BPSY23\n"
    "    If RR22: provide ns_log nr_log\n"
    "    If BPSY23: provide n_log\n\n"
    "Examples:\n"
    "  " << prog << " 0 0 20 20     # PSI + RR22, ns=2^20, nr=2^20\n"
    "  " << prog << " 0 1 20        # PSI + BPSY23, n=2^20\n"
    "  " << prog << " 1 0 20 20     # CPSI + RR22, ns=2^20, nr=2^20\n"
    "  " << prog << " 1 1 20        # CPSI + BPSY23, n=2^24\n\n"
    "Usage (explicit flags):\n"
    "  --mode=psi|cpsi  --okvs=rr22|bpsy23  --ns-log=K  --nr-log=L  --n-log=M\n"
    "  RR22 requires --ns-log and --nr-log; BPSY23 requires --n-log\n";
}


static bool parse_int(const string& s, int& out) {
  try {
    size_t pos = 0;
    int64_t v = stoll(s, &pos, 10);
    if (pos != s.size()) { return false;
}
    if (v < 0 || v > 62) { return false; // keep shifts safe
}
    out = static_cast<int>(v);
    return true;
  } catch (...) { return false; }
}


int main(int argc, char** argv) {
  int      g_ns_log = -1;
  int      g_nr_log = -1;
  int      g_n_log = -1;
  uint64_t g_ns     = 0;
  uint64_t g_nr     = 0;
  uint64_t g_n    = 0;
  ios::sync_with_stdio(false);
  cin.tie(nullptr);

  Mode mode = Mode::PSI;
  OKVS okvs = OKVS::RR22;

  bool has_mode = false;
  bool has_okvs = false;
  bool need_rr22 = false;
  bool need_bpsy = false;

  int ns_log = -1;
  int nr_log = -1;
  int n_log = -1;

  auto tolower_str = [](string s){
    for (auto& c : s) { c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
}
    return s;
  };

  // 1) Numeric shorthand takes precedence
  if (argc >= 3 && (string(argv[1])=="0" || string(argv[1])=="1")
                && (string(argv[2])=="0" || string(argv[2])=="1")) {
    mode = (argv[1][0]=='0') ? Mode::PSI : Mode::CPSI;
    has_mode = true;

    okvs = (argv[2][0]=='0') ? OKVS::RR22 : OKVS::BPSY23;
    has_okvs = true;

    

    if (okvs == OKVS::RR22) {
      if (argc < 5) { print_usage(argv[0]); return 1; }
      if (!parse_int(argv[3], ns_log) || !parse_int(argv[4], nr_log)) {
        cerr << "Error: ns_log / nr_log must be integers in [0, 62].\n";
        return 1;
      }
      need_rr22 = true;
    } else {
      if (argc < 4) { print_usage(argv[0]); return 1; }
      if (!parse_int(argv[3], n_log)) {
        cerr << "Error: n_log must be an integer in [0, 62].\n";
        return 1;
      }
      need_bpsy = true;
    }
  } else {
    // 2) Explicit flags
    for (int i = 1; i < argc; ++i) {
      string arg = argv[i];
      if (arg.rfind("--mode=", 0) == 0) {
        string v = tolower_str(arg.substr(7));
        if (v == "psi")      { mode = Mode::PSI; has_mode = true; }
        else if (v == "cpsi"){ mode = Mode::CPSI; has_mode = true; }
        else { cerr << "Unknown --mode value: " << v << "\n"; return 1; }
      } else if (arg.rfind("--okvs=", 0) == 0) {
        string v = tolower_str(arg.substr(7));
        if (v == "rr22")     { okvs = OKVS::RR22; has_okvs = true; }
        else if (v == "bpsy23" || v == "bpsy") {
          okvs = OKVS::BPSY23; has_okvs = true;
        } else { cerr << "Unknown --okvs value: " << v << "\n"; return 1; }
      } else if (arg.rfind("--ns-log=", 0) == 0) {
        if (!parse_int(arg.substr(9), ns_log)) { cerr << "Invalid --ns-log\n"; return 1; }
      } else if (arg.rfind("--nr-log=", 0) == 0) {
        if (!parse_int(arg.substr(9), nr_log)) { cerr << "Invalid --nr-log\n"; return 1; }
      } else if (arg.rfind("--n-log=", 0) == 0) {
        if (!parse_int(arg.substr(8), n_log)) { cerr << "Invalid --n-log\n"; return 1; }
      } else if (arg == "-h" || arg == "--help") {
        print_usage(argv[0]); return 0;
      } else {
        cerr << "Unknown argument: " << arg << "\n";
        print_usage(argv[0]); return 1;
      }
    }

    if (!has_mode || !has_okvs) {
      print_usage(argv[0]); return 1;
    }
    if (okvs == OKVS::RR22) {
      if (ns_log < 0 || nr_log < 0) {
        cerr << "RR22 requires --ns-log and --nr-log.\n";
        return 1;
      }
      need_rr22 = true;
    } else {
      if (n_log < 0) {
        cerr << "BPSY23 requires --n-log.\n";
        return 1;
      }
      need_bpsy = true;
    }
  }

  // Compute sizes and store into globals
  if (need_rr22) {
    g_ns_log = ns_log; g_nr_log = nr_log;
    g_ns = (ns_log >= 64 ? 0 : (1ULL << ns_log));
    g_nr = (nr_log >= 64 ? 0 : (1ULL << nr_log));
    if ((g_ns == 0U) || (g_nr == 0U)) { cerr << "Shift too large; use log values <= 62.\n"; return 1; }
  } else if (need_bpsy) {
    g_n_log = n_log;
    g_n = (n_log >= 64 ? 0 : (1ULL << n_log));
    if (g_n == 0U) { cerr << "Shift too large; use log values <= 62.\n"; return 1; }
  }

  // Confirmation
  cout << "=== Run Config ===\n";
  cout << "Mode: " << (mode == Mode::PSI ? "PSI" : "CPSI") << "\n";
  cout << "OKVS: " << (okvs == OKVS::RR22 ? "RR22" : "BPSY23") << "\n";
  if (okvs == OKVS::RR22) {
    cout << "ns_log=" << g_ns_log << " (ns=" << g_ns << "), "
         << "nr_log=" << g_nr_log << " (nr=" << g_nr << ")\n";
  } else {
    cout << "n_log=" << g_n_log << " (n=" << g_n << ")\n";
  }
  cout << "==================\n";

  // Dispatch
  if (mode == Mode::PSI) {
    if (okvs == OKVS::RR22) {
      OurPSIRR22SHA2(g_ns_log, g_nr_log);
      OurSemiPSIRR22SHA2(g_ns_log,g_nr_log);   // also run Semi variant under PSI
    } else {
      OurPSIBPSYSHA2(g_n_log,g_n_log);
      OurSemiPSIBPSYSHA2(g_n_log);   // also run Semi variant under PSI
    }
  } else { // CPSI
    if (okvs == OKVS::RR22) {
      OurCPSIRR22SHA2(g_ns_log,g_nr_log);
    } else {
      OurCPSIBPSYSHA2(g_n_log);
    }
  }

  return 0;
}


