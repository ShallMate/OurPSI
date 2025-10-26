# ------------------------------------------------------------
# Base
# ------------------------------------------------------------
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
SHELL ["/bin/bash", "-lc"]


RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        build-essential \
        git \
        curl \
        wget \
        ca-certificates \
        python3 \
        python3-distutils \
        ninja-build \
        perl \
        autoconf \
        automake \
        libtool \
        openjdk-11-jdk \
        unzip && \
    add-apt-repository -y ppa:ubuntu-toolchain-r/test && \
    apt-get update && \
    apt-get install -y gcc-11 g++-11 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 60 \
      --slave /usr/bin/g++ g++ /usr/bin/g++-11 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# CMake 3.24.2
# ------------------------------------------------------------
RUN mkdir -p /opt && \
    wget -q https://github.com/Kitware/CMake/releases/download/v3.24.2/cmake-3.24.2-linux-x86_64.tar.gz -O - \
    | tar -xz -C /opt && \
    ln -sfn /opt/cmake-3.24.2-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -sfn /opt/cmake-3.24.2-linux-x86_64/bin/ctest /usr/local/bin/ctest && \
    ln -sfn /opt/cmake-3.24.2-linux-x86_64/bin/cpack /usr/local/bin/cpack

ENV CC=/usr/bin/gcc-11 CXX=/usr/bin/g++-11

# ------------------------------------------------------------
#  cryptoTools（Boost/RELIC）
# ------------------------------------------------------------
WORKDIR /opt
RUN git clone https://github.com/ladnir/cryptoTools.git && \
    cd cryptoTools && \
    python3 build.py --setup --boost --relic --install && \
    python3 build.py --install

# ------------------------------------------------------------
# Bazel 6.5.0
# ------------------------------------------------------------
WORKDIR /opt
RUN wget -q https://releases.bazel.build/6.5.0/release/bazel-6.5.0-installer-linux-x86_64.sh && \
    chmod +x bazel-6.5.0-installer-linux-x86_64.sh && \
    ./bazel-6.5.0-installer-linux-x86_64.sh --prefix=/usr/local && \
    rm bazel-6.5.0-installer-linux-x86_64.sh

# ------------------------------------------------------------
# YACL
# ------------------------------------------------------------
WORKDIR /opt
RUN git clone https://github.com/ShallMate/yacl.git
WORKDIR /opt/yacl
RUN rm -f WORKSPACE BUILD.bazel && \
    mv WORKSPACE_without_APSI WORKSPACE && \
    mv BUILD_without_APSI.bazel BUILD.bazel && \
    mkdir -p examples


COPY otokvspsi/ /opt/yacl/examples/otokvspsi/

# ------------------------------------------------------------
RUN bazel --version && \
    bazel build --experimental_cc_shared_library --linkopt=-ldl //... --cxxopt='-std=c++17'

CMD ["/bin/bash"]

