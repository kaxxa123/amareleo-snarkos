FROM ubuntu:24.04 AS builder

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    DEBIAN_FRONTEND=noninteractive

RUN set -eux ; \
    apt update -y && \
    apt dist-upgrade -o DPkg::Options::=--force-confold -y && \
    apt install -o DPkg::Options::=--force-confold --no-install-recommends -y \
        ca-certificates \
        gcc \
        libc6-dev \
        wget \
        build-essential \
        clang \
        gcc \
        libssl-dev \
        make \
        pkg-config \
        xz-utils && \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    \
    url="https://static.rust-lang.org/rustup/dist/${rustArch}/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain stable; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version

WORKDIR /usr/src/snarkOS

COPY . .

RUN cargo build --release

#---
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

VOLUME ["/aleo/data"]

COPY --from=builder /usr/src/snarkOS/entrypoint.sh /aleo/

RUN set -ex && \
    apt update && \
    apt dist-upgrade -o DPkg::Options::=--force-confold -y && \
    apt install -o DPkg::Options::=--force-confold --no-install-recommends -y ca-certificates && \
    apt purge --auto-remove -o APT::AutoRemove::RecommendsImportant=false -y && \
    apt clean && \
    ln -s /aleo/data /root/.aleo && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /aleo/{bin,data}

COPY --from=builder /usr/src/snarkOS/target/release/snarkos /aleo/bin/

CMD ["/aleo/entrypoint.sh"]
