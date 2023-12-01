FROM rust:slim-buster

RUN dpkg --add-architecture armhf && dpkg --add-architecture arm64

RUN apt-get update && apt-get install -qy dpkg-dev g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf g++-aarch64-linux-gnu binutils-aarch64-linux-gnu

RUN rustup target add armv7-unknown-linux-gnueabihf aarch64-unknown-linux-gnu

RUN cargo install cargo-deb && rm -rf ~/.cargo/registry

WORKDIR /volume
ENTRYPOINT ["cargo-deb"]
