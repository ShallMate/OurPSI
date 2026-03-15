# syntax=docker/dockerfile:1.7

FROM ubuntu:22.04 AS deps

ARG DEBIAN_FRONTEND=noninteractive
ARG BAZEL_VERSION=6.5.0
ARG LIBOTE_REPO=https://github.com/osu-crypto/libOTe.git
ARG LIBOTE_REF=d55867114c78272be7142bd67ebdcb346fec8621

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64:${LD_LIBRARY_PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    file \
    git \
    libgflags-dev \
    libgmp-dev \
    libgoogle-glog-dev \
    libssl-dev \
    libtool \
    nasm \
    ninja-build \
    openjdk-17-jdk-headless \
    perl \
    pkg-config \
    python3 \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/bazel \
      "https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-x86_64" \
    && chmod +x /usr/local/bin/bazel

WORKDIR /tmp

RUN git clone "${LIBOTE_REPO}" libOTe \
    && git -C libOTe checkout "${LIBOTE_REF}" \
    && git -C libOTe submodule update --init --recursive \
    && cmake -S libOTe -B libOTe/out/build/linux \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX=/usr/local \
         -DNO_SYSTEM_PATH=ON \
         -DFETCH_AUTO=ON \
         -DENABLE_CIRCUITS=ON \
         -DENABLE_MRR=ON \
         -DENABLE_IKNP=ON \
         -DENABLE_SOFTSPOKEN_OT=ON \
         -DENABLE_BITPOLYMUL=ON \
         -DENABLE_SILENTOT=ON \
         -DENABLE_SILENT_VOLE=ON \
         -DENABLE_SSE=ON \
         -DENABLE_BOOST=ON \
         -DLIBOTE_STD_VER=20 \
         -DENABLE_SODIUM=ON \
         -DSODIUM_MONTGOMERY=ON \
    && cmake --build libOTe/out/build/linux --parallel "$(nproc)" \
    && cmake --install libOTe/out/build/linux --prefix /usr/local \
    && mkdir -p /usr/local/include/securejoin/out/libOTe \
               /usr/local/include/secure-join/out/libOTe \
    && cp -a libOTe/thirdparty /usr/local/include/securejoin/out/libOTe/ \
    && cp -a libOTe/thirdparty /usr/local/include/secure-join/out/libOTe/ \
    && ldconfig \
    && rm -rf /tmp/libOTe

FROM deps AS builder

ARG YACL_REPO=https://github.com/ShallMate/yacl.git
ARG YACL_REF=f2c6c5ba8d4c475608018a53b75e4b3d62a3112a

WORKDIR /src

RUN git clone "${YACL_REPO}" yacl \
    && git -C yacl checkout "${YACL_REF}"

COPY . /src/yacl/examples/otokvspsi/

WORKDIR /src/yacl

RUN bazel --batch build \
    --experimental_cc_shared_library \
    --cxxopt=-std=c++17 \
    --host_cxxopt=-std=c++17 \
    //examples/otokvspsi:ourpsi

WORKDIR /src/yacl/examples/otokvspsi

CMD ["/src/yacl/bazel-bin/examples/otokvspsi/ourpsi"]

