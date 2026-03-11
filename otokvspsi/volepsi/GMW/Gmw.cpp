#include "Gmw.h"

#include <array>
#include <numeric>

#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "libOTe/Tools/Tools.h"
#include "yacl/utils/parallel.h"

namespace volePSI {
using PRNG = oc::PRNG;

namespace {

template <typename Fn>
void ParallelForBlocks(u64 num_threads, u64 n, Fn&& fn) {
  if (n == 0) {
    return;
  }
  if (num_threads <= 1 || n < 1024) {
    fn(0, n);
    return;
  }
  yacl::parallel_for(0, static_cast<int64_t>(n),
                     [&](int64_t begin, int64_t end) {
                       fn(static_cast<u64>(begin), static_cast<u64>(end));
                     });
}

}  // namespace

void Gmw::init(u64 n, BetaCircuit& cir, u64 numThreads, u64 pIdx, block seed) {
  mIdx = pIdx;
  mN = n;
  mNumThreads = std::max<u64>(1, numThreads);

  mRoundIdx = 0;
  mCir = cir;

  mCir.levelByAndDepth(mLevelize);
  mNumRounds = mCir.mLevelCounts.size();

  mGates = mCir.mGates;
  mWords.resize(mCir.mWireCount, oc::divCeil(mN, 128));

  memset(mWords.data(), 0, mWords.size() * sizeof(*mWords.data()));

  mPrng.SetSeed(seed);
  mPhiPrng.SetSeed(mPrng.get(), mWords.cols());

  mNumOts = mWords.cols() * 128 * mCir.mNonlinearGateCount * 2;

  mPrint = mCir.mPrints.begin();
}

Proto Gmw::generateTriple(u64 batchSize, u64 numThreads,
                          coproto::Socket& chl) {
  auto A2 = std::vector<block>{};
  auto B2 = std::vector<block>{};
  auto C2 = std::vector<block>{};
  auto D2 = std::vector<block>{};
  auto mid = mNumOts / 128 / 2;

  if (mNumOts == 0) {
    co_return;
  }

  auto& tg = mSilent;
  setTimePoint("Gmw::generateTriple begin");
  if (mTimer) {
    tg.setTimer(*mTimer);
  }

  tg.init(mNumOts, batchSize, numThreads, mIdx ? Mode::Receiver : Mode::Sender,
          mPrng.get());
  if (tg.hasBaseOts() == false) {
    co_await(tg.generateBaseOts(mIdx, mPrng, chl));
  }

  co_await(tg.expand(chl));
  if (mIdx) {
    mA = tg.mMult.subspan(0, mid);
    mC = tg.mMult.subspan(mid);
    mC2 = tg.mMult.subspan(mid);
    mB = tg.mAdd.subspan(0, mid);
    mD = tg.mAdd.subspan(mid);
  } else {
    mA = tg.mMult.subspan(mid);
    mC = tg.mMult.subspan(0, mid);
    mC2 = tg.mMult.subspan(0, mid);
    mB = tg.mAdd.subspan(mid);
    mD = tg.mAdd.subspan(0, mid);
  }

  if (mO.mDebug) {
    A2.resize(mA.size());
    B2.resize(mA.size());
    C2.resize(mA.size());
    D2.resize(mA.size());

    co_await(chl.send(coproto::copy(mA)));
    co_await(chl.send(coproto::copy(mB)));
    co_await(chl.send(coproto::copy(mC)));
    co_await(chl.send(coproto::copy(mD)));

    co_await(chl.recv(A2));
    co_await(chl.recv(B2));
    co_await(chl.recv(C2));
    co_await(chl.recv(D2));

    for (u64 i = 0; i < mA.size(); ++i) {
      if (neq((mA[i] & C2[i]) ^ mB[i], D2[i])) {
        std::cout << "bad triple at 0." << i << ", n " << mNumOts
                  << std::endl;
        throw std::runtime_error("");
      }

      if (neq((A2[i] & mC[i]) ^ B2[i], mD[i])) {
        std::cout << "bad triple at 1." << i << ", n " << mNumOts
                  << std::endl;
        throw std::runtime_error("");
      }
    }
  }

  setTimePoint("Gmw::generateTriple end");
}

void Gmw::implSetInput(u64 i, oc::MatrixView<u8> input, u64 alignment) {
  oc::MatrixView<u8> memView = getInputView(i);

  auto numWires = memView.rows();
  auto bits = alignment * 8;

  auto exp = (numWires + bits - 1) / bits;
  auto act = input.cols() / alignment;
  if (exp != act) {
    throw RTE_LOC;
  }

  if (input.rows() != mN) {
    throw RTE_LOC;
  }

  oc::transpose(input, memView);
}

void Gmw::setZeroInput(u64 i) {
  oc::MatrixView<u8> memView = getInputView(i);
  memset(memView.data(), 0, memView.size());
}

Proto Gmw::run(coproto::Socket& chl) {
  auto i = u64{};

  if (mA.size() == 0) {
    co_await(generateTriple(1 << 20, mNumThreads, chl));
  }

  if (mO.mDebug) {
    mO.mWords.resize(mWords.rows(), mWords.cols());

    co_await(chl.send(coproto::copy(mWords)));
    co_await(chl.recv(mO.mWords));

    for (i = 0; i < mWords.size(); i++) {
      mO.mWords(i) = mO.mWords(i) ^ mWords(i);
    }
  }

  mRoundIdx = 0;

  for (i = 0; i < numRounds(); ++i) {
    co_await(roundFunction(chl));
  }

  mA = {};
}

void Gmw::implGetOutput(u64 i, oc::MatrixView<u8> out, u64 alignment) {
  oc::MatrixView<u8> memView = getOutputView(i);

  auto numWires = memView.rows();
  auto bits = alignment * 8;

  if ((numWires + bits - 1) / bits != out.cols() / alignment) {
    throw RTE_LOC;
  }

  if (out.rows() != mN) {
    throw RTE_LOC;
  }

  oc::transpose(memView, out);
}

oc::MatrixView<u8> Gmw::getInputView(u64 i) {
  if (mCir.mInputs.size() <= i) {
    throw RTE_LOC;
  }

  auto& inWires = mCir.mInputs[i];

  return getMemView(inWires);
}

oc::MatrixView<u8> Gmw::getOutputView(u64 i) {
  if (mCir.mOutputs.size() <= i) {
    throw RTE_LOC;
  }

  auto& wires = mCir.mOutputs[i];

  return getMemView(wires);
}

oc::MatrixView<u8> Gmw::getMemView(BetaBundle& wires) {
  for (u64 j = 1; j < wires.size(); ++j) {
    if (wires[j - 1] + 1 != wires[j]) {
      throw RTE_LOC;
    }
  }

  oc::MatrixView<u8> memView((u8*)mWords[wires[0]].data(), wires.size(),
                             mWords.cols() * 16);
  return memView;
}

Proto Gmw::roundFunction(coproto::Socket& chl) {
  auto gates = span<oc::BetaGate>{};
  auto gate = span<oc::BetaGate>::iterator{};
  auto dirtyBits = std::vector<u8>{};
  auto pinnedInputs = std::vector<u8>{};
  auto in = std::array<span<block>, 2>{};
  auto out = span<block>{};
  auto ww = std::vector<block>{};
  auto print = coproto::unique_function<void(u64)>{};

  if (mRoundIdx >= mNumRounds) {
    throw std::runtime_error("round function called too many times");
  }

  gates = mGates.subspan(0, mCir.mLevelCounts[mRoundIdx]);
  mGates = mGates.subspan(mCir.mLevelCounts[mRoundIdx]);

  if (mO.mDebug) {
    dirtyBits.resize(mCir.mWireCount, 0);
    pinnedInputs.resize(mCir.mWireCount, 0);
  }

  for (gate = gates.begin(); gate < gates.end(); ++gate) {
    in = {mWords[gate->mInput[0]], mWords[gate->mInput[1]]};
    out = mWords[gate->mOutput];

    if (mO.mDebug) {
      if (dirtyBits[gate->mInput[0]] ||
          (dirtyBits[gate->mInput[1]] && gate->mType != oc::GateType::a)) {
        throw std::runtime_error(
            "incorrect levelization, input to current gate depends on the "
            "output of the current round. " LOCATION);
      }

      if (pinnedInputs[gate->mOutput]) {
        throw std::runtime_error(
            "incorrect levelization, overwriting an input which is being used "
            "in the current round. " LOCATION);
      }
    }

    if (gate->mType == oc::GateType::a) {
      ParallelForBlocks(mNumThreads, out.size(), [&](u64 begin, u64 end) {
        for (u64 i = begin; i < end; ++i) {
          out[i] = in[0][i];
        }
      });
    } else if (gate->mType == oc::GateType::na_And ||
               gate->mType == oc::GateType::nb_And ||
               gate->mType == oc::GateType::And ||
               gate->mType == oc::GateType::Nor ||
               gate->mType == oc::GateType::Or) {
      co_await(multSend(in[0], in[1], chl, gate->mType));

      if (mO.mDebug) {
        pinnedInputs[gate->mInput[0]] = 1;
        pinnedInputs[gate->mInput[1]] = 1;
        dirtyBits[gate->mOutput] = 1;
      }
    } else if (gate->mType == oc::GateType::Xor ||
               gate->mType == oc::GateType::Nxor) {
      const bool invert_output = gate->mType == oc::GateType::Nxor && mIdx == 0;
      ParallelForBlocks(mNumThreads, out.size(), [&](u64 begin, u64 end) {
        for (u64 i = begin; i < end; ++i) {
          out[i] = in[0][i] ^ in[1][i];
          if (invert_output) {
            out[i] = out[i] ^ oc::AllOneBlock;
          }
        }
      });
    } else {
      throw RTE_LOC;
    }
  }

  for (gate = gates.begin(); gate < gates.end(); ++gate) {
    in = {mWords[gate->mInput[0]], mWords[gate->mInput[1]]};
    out = mWords[gate->mOutput];

    if (gate->mType == oc::GateType::na_And ||
        gate->mType == oc::GateType::nb_And ||
        gate->mType == oc::GateType::And ||
        gate->mType == oc::GateType::Or ||
        gate->mType == oc::GateType::Nor) {
      co_await(multRecv(in[0], in[1], out, chl, gate->mType));
    }
  }

  if (mO.mDebug) {
    print = [&](u64 gIdx) {
      while (mDebugPrintIdx < mN && mPrint != mCir.mPrints.end() &&
             mPrint->mGateIdx <= gIdx && mIdx) {
        auto wireIdx = mPrint->mWire;
        auto invert = mPrint->mInvert;

        if (wireIdx != ~u32(0)) {
          oc::BitIterator iter((u8*)mO.mWords[wireIdx].data(), mDebugPrintIdx);
          auto mem = u64(*iter);
          std::cout << (u64)(mem ^ (invert ? 1 : 0));
        }
        if (mPrint->mMsg.size()) {
          std::cout << mPrint->mMsg;
        }

        ++mPrint;
      }
    };

    for (auto& gate_ref : gates) {
      auto gIdx = &gate_ref - mCir.mGates.data();
      print(gIdx);

      for (u64 i = 0; i < mWords.cols(); ++i) {
        auto& a = mO.mWords(gate_ref.mInput[0], i);
        auto& b = mO.mWords(gate_ref.mInput[1], i);
        auto& c = mO.mWords(gate_ref.mOutput, i);

        switch (gate_ref.mType) {
          case oc::GateType::a:
            c = a;
            break;
          case oc::GateType::And:
            c = a & b;
            break;
          case oc::GateType::Or:
            c = a | b;
            break;
          case oc::GateType::Nor:
            c = (a | b) ^ oc::AllOneBlock;
            break;
          case oc::GateType::nb_And:
            c = a & (oc::AllOneBlock ^ b);
            break;
          case oc::GateType::na_And:
            c = (oc::AllOneBlock ^ a) & b;
            break;
          case oc::GateType::Xor:
            c = a ^ b;
            break;
          case oc::GateType::Nxor:
            c = a ^ b ^ oc::AllOneBlock;
            break;
          default:
            throw RTE_LOC;
        }
      }
    }

    if (mGates.size() == 0) {
      print(mCir.mGates.size());
    }

    co_await(chl.send(coproto::copy(mWords)));

    ww.resize(mWords.size());
    co_await(chl.recv(ww));

    for (u64 i = 0; i < mWords.size(); ++i) {
      auto exp = mO.mWords(i);
      auto act = ww[i] ^ mWords(i);

      if (neq(exp, act)) {
        auto row = (i / mWords.cols());
        auto col = (i % mWords.cols());

        oc::lout << "p" << mIdx << " mem[" << row << ", " << col
                 << "] exp: " << exp << ", act: " << act << std::endl;

        throw RTE_LOC;
      }
    }
  }

  ++mRoundIdx;
}

oc::BitVector view(block v, u64 l = 10) {
  return oc::BitVector((u8*)&v, l);
}

namespace {

bool invertA(oc::GateType gt) {
  bool invertX;
  switch (gt) {
    case osuCrypto::GateType::na_And:
    case osuCrypto::GateType::Or:
    case osuCrypto::GateType::Nor:
      invertX = true;
      break;
    case osuCrypto::GateType::And:
    case osuCrypto::GateType::nb_And:
      invertX = false;
      break;
    default:
      throw RTE_LOC;
  }

  return invertX;
}

bool invertB(oc::GateType gt) {
  bool invertX;
  switch (gt) {
    case osuCrypto::GateType::nb_And:
    case osuCrypto::GateType::Nor:
    case osuCrypto::GateType::Or:
      invertX = true;
      break;
    case osuCrypto::GateType::na_And:
    case osuCrypto::GateType::And:
      invertX = false;
      break;
    default:
      throw RTE_LOC;
  }

  return invertX;
}

bool invertC(oc::GateType gt) {
  bool invertX;
  switch (gt) {
    case osuCrypto::GateType::Or:
      invertX = true;
      break;
    case osuCrypto::GateType::na_And:
    case osuCrypto::GateType::nb_And:
    case osuCrypto::GateType::Nor:
    case osuCrypto::GateType::And:
      invertX = false;
      break;
    default:
      throw RTE_LOC;
  }

  return invertX;
}

}  // namespace

Proto Gmw::multSendP1(span<block> x, coproto::Socket& chl, oc::GateType gt) {
  auto width = x.size();
  auto a = span<block>{};
  auto u = std::vector<block>{};
  a = mA.subspan(0, width);
  mA = mA.subspan(width);

  u.resize(width);
  if (invertA(gt) == false) {
    ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
      for (u64 i = begin; i < end; ++i) {
        u[i] = a[i] ^ x[i];
      }
    });
  } else {
    ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
      for (u64 i = begin; i < end; ++i) {
        u[i] = a[i] ^ x[i] ^ oc::AllOneBlock;
      }
    });
  }

  co_await(chl.send(std::move(u)));
}

Proto Gmw::multSendP2(span<block> y, coproto::Socket& chl, oc::GateType gt) {
  auto width = y.size();
  auto c = span<block>{};
  auto w = std::vector<block>{};

  c = mC.subspan(0, width);
  mC = mC.subspan(width);

  w.resize(width);
  if (invertB(gt) == false) {
    ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
      for (u64 i = begin; i < end; ++i) {
        w[i] = c[i] ^ y[i];
      }
    });
  } else {
    ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
      for (u64 i = begin; i < end; ++i) {
        w[i] = c[i] ^ (y[i] ^ oc::AllOneBlock);
      }
    });
  }

  co_await(chl.send(std::move(w)));
}

Proto Gmw::multRecvP1(span<block> x, span<block> z, coproto::Socket& chl,
                      oc::GateType gt) {
  auto width = x.size();
  auto b = span<block>{};
  auto w = std::vector<block>{};
  w.resize(width);
  co_await(chl.recv(w));

  b = mB.subspan(0, width);
  mB = mB.subspan(width);

  if (invertA(gt) == false) {
    ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
      for (u64 i = begin; i < end; ++i) {
        z[i] = (x[i] & w[i]) ^ b[i];
      }
    });
  } else {
    ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
      for (u64 i = begin; i < end; ++i) {
        z[i] = ((oc::AllOneBlock ^ x[i]) & w[i]) ^ b[i];
      }
    });
  }
}

Proto Gmw::multRecvP2(span<block> y, span<block> z, coproto::Socket& chl) {
  auto width = y.size();
  auto c = span<block>{};
  auto d = span<block>{};
  auto u = std::vector<block>{};

  u.resize(width);
  co_await(chl.recv(u));

  c = mC2.subspan(0, width);
  mC2 = mC2.subspan(width);
  d = mD.subspan(0, width);
  mD = mD.subspan(width);

  ParallelForBlocks(mNumThreads, width, [&](u64 begin, u64 end) {
    for (u64 i = begin; i < end; ++i) {
      z[i] = (c[i] & u[i]) ^ d[i];
    }
  });
}

Proto Gmw::multSendP1(span<block> x, span<block> y, coproto::Socket& chl,
                      oc::GateType gt) {
  co_await(multSendP1(x, chl, gt));
  co_await(multSendP2(y, chl, gt));
}

Proto Gmw::multSendP2(span<block> x, span<block> y, coproto::Socket& chl) {
  co_await(multSendP2(y, chl, oc::GateType::And));
  co_await(multSendP1(x, chl, oc::GateType::And));
}

Proto Gmw::multRecvP1(span<block> x, span<block> y, span<block> z,
                      coproto::Socket& chl, oc::GateType gt) {
  auto zz = std::vector<block>{};
  auto zz2 = std::vector<block>{};
  auto xm = block{};
  auto ym = block{};
  auto zm = block{};

  zz.resize(z.size());
  zz2.resize(z.size());
  co_await(multRecvP1(x, zz, chl, gt));
  co_await(multRecvP2(y, zz2, chl));

  xm = invertA(gt) ? oc::AllOneBlock : oc::ZeroBlock;
  ym = invertB(gt) ? oc::AllOneBlock : oc::ZeroBlock;
  zm = invertC(gt) ? oc::AllOneBlock : oc::ZeroBlock;

  ParallelForBlocks(mNumThreads, zz.size(), [&](u64 begin, u64 end) {
    for (u64 i = begin; i < end; ++i) {
      auto xx = x[i] ^ xm;
      auto yy = y[i] ^ ym;
      z[i] = xx & yy;
      z[i] = z[i] ^ zz[i];
      z[i] = z[i] ^ zz2[i];
      z[i] = z[i] ^ zm;
    }
  });
}

Proto Gmw::multRecvP2(span<block> x, span<block> y, span<block> z,
                      coproto::Socket& chl) {
  auto zz = std::vector<block>{};
  auto zz2 = std::vector<block>{};

  zz.resize(z.size());
  zz2.resize(z.size());

  co_await(multRecvP2(y, zz, chl));
  co_await(multRecvP1(x, zz2, chl, oc::GateType::And));

  ParallelForBlocks(mNumThreads, zz.size(), [&](u64 begin, u64 end) {
    for (u64 i = begin; i < end; ++i) {
      z[i] = zz2[i] ^ zz[i] ^ (x[i] & y[i]);
    }
  });
}

}  // namespace volePSI
