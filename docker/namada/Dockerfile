FROM rust:1.65.0-slim-buster AS namada-builder
ARG BRANCH=v0.16.0
WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    clang-tools-11 \
    git \
    libssl-dev \
    pkg-config \
    musl-dev \
    unzip \
    && apt-get clean

# install protoc
ADD https://github.com/protocolbuffers/protobuf/releases/download/v23.1/protoc-23.1-linux-x86_64.zip /tmp/protoc.zip
RUN unzip /tmp/protoc.zip -d /usr/local
RUN rm -rf /tmp/protoc.zip

# for wasm
RUN rustup target add wasm32-unknown-unknown
# Download binaryen and extract wasm-opt
ADD https://github.com/WebAssembly/binaryen/releases/download/version_113/binaryen-version_113-x86_64-linux.tar.gz /tmp/binaryen.tar.gz
RUN tar -xf /tmp/binaryen.tar.gz
RUN mv binaryen-version_*/bin/wasm-opt /usr/local/bin
RUN rm -rf binaryen-version_*/ /tmp/binaryen.tar.gz

# namada binaries
RUN git clone -b $BRANCH --single-branch \
    https://github.com/anoma/namada.git \
    && cd namada \
    && make build

FROM rust:1.65.0-slim-buster AS namada-wasm-builder
ARG BRANCH=v0.16.0
WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    clang-tools-11 \
    git \
    libssl-dev \
    pkg-config \
    musl-dev \
    unzip \
    && apt-get clean

# install protoc
ADD https://github.com/protocolbuffers/protobuf/releases/download/v23.1/protoc-23.1-linux-x86_64.zip /tmp/protoc.zip
RUN unzip /tmp/protoc.zip -d /usr/local
RUN rm -rf /tmp/protoc.zip

# for wasm
RUN rustup target add wasm32-unknown-unknown
# Download binaryen and extract wasm-opt
ADD https://github.com/WebAssembly/binaryen/releases/download/version_113/binaryen-version_113-x86_64-linux.tar.gz /tmp/binaryen.tar.gz
RUN tar -xf /tmp/binaryen.tar.gz
RUN mv binaryen-version_*/bin/wasm-opt /usr/local/bin
RUN rm -rf binaryen-version_*/ /tmp/binaryen.tar.gz

# namada wasm
RUN git clone -b $BRANCH --single-branch \
    https://github.com/anoma/namada.git \
    && cd namada \
    && make build-wasm-scripts

# for tendermint
FROM golang:1.18.0 as tendermint-builder
ARG TENDERMINT_VERSION=v0.1.4-abciplus
WORKDIR /app
RUN git clone -b $TENDERMINT_VERSION --single-branch \
    https://github.com/heliaxdev/tendermint.git \
    && cd tendermint \
    && make build

FROM debian:bullseye-slim AS runtime
ENV NAMADA_BASE_DIR=/home/namada/chains
ENV NAMADA_LOG_COLOR=false
ENV TM_LOG_LEVEL=p2p:error,pex:error 
ENV NAMADA_TM_STDOUT=true

RUN apt-get update && apt-get install libcurl4-openssl-dev -y && apt-get clean

RUN useradd --create-home namada
USER namada
RUN mkdir /home/namada/genesis
RUN mkdir /home/namada/wasm
RUN mkdir /home/namada/chains

COPY --from=namada-builder --chown=namada:namada --chmod=0755 /app/namada/target/debug/namada /usr/local/bin
COPY --from=namada-builder --chown=namada:namada --chmod=0755 /app/namada/target/debug/namadan /usr/local/bin
COPY --from=namada-builder --chown=namada:namada --chmod=0755 /app/namada/target/debug/namadaw /usr/local/bin
COPY --from=namada-builder --chown=namada:namada --chmod=0755 /app/namada/target/debug/namadac /usr/local/bin
COPY --from=namada-wasm-builder --chown=namada:namada /app/namada/wasm/checksums.json /home/namada/wasm
COPY --from=namada-wasm-builder --chown=namada:namada /app/namada/wasm/*.wasm /home/namada/wasm
COPY --from=namada-builder --chown=namada:namada /app/namada/genesis/e2e-tests-single-node.toml /home/namada/genesis
COPY --from=tendermint-builder --chown=namada:namada --chmod=0755 /app/tendermint/build/tendermint /usr/local/bin

EXPOSE 26656
EXPOSE 26660
EXPOSE 26659
EXPOSE 26657

ENV GENESIS_PATH=/home/namada/genesis/e2e-tests-single-node.toml
ENV CHECKSUM_PATH=/home/namada/wasm/checksums.json
RUN rm /home/namada/genesis/e2e-tests-single-node.toml
COPY e2e-tests-single-node.toml /home/namada/genesis
COPY --chown=namada:namada --chmod=0755 setup-namada.sh /home/namada
COPY --chown=namada:namada --chmod=0755 run-namada.sh /home/namada

RUN ./home/namada/setup-namada.sh

CMD ["./home/namada/run-namada.sh"]
