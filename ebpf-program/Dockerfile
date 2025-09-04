FROM ubuntu:25.10

RUN apt-get update -y && apt-get dist-upgrade -y && \
    apt-get install -y sudo less lsb-release \
        curl wget make git cmake unzip libc6-dev g++ gcc pkgconf \
        musl-dev bpftool clang libbpf-dev && \
    apt-get clean autoclean && \
    apt-get autoremove --yes

RUN userdel -r ubuntu && useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

WORKDIR /app/
