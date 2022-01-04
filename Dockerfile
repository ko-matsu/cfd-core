FROM python:3.9.7-slim-buster as cfd_core_base

# install dependencies
RUN apt update && apt install -y \
    gpg \
    wget \
    build-essential \
    git \
    valgrind \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
ENV GPG_KEY_SERVER hkps://keyserver.ubuntu.com

# setup cmake
ENV CMAKE_VERSION 3.21.3
ENV CMAKE_TARBALL cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz
ENV CMAKE_URL_BASE https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}
ENV CMAKE_PGP_KEY 2D2CEF1034921684
RUN wget -qO ${CMAKE_TARBALL} ${CMAKE_URL_BASE}/${CMAKE_TARBALL} \
  && gpg --keyserver ${GPG_KEY_SERVER} --recv-keys ${CMAKE_PGP_KEY} \
  && wget -qO cmake-SHA-256.txt ${CMAKE_URL_BASE}/cmake-${CMAKE_VERSION}-SHA-256.txt \
  && wget -qO cmake-SHA-256.txt.asc ${CMAKE_URL_BASE}/cmake-${CMAKE_VERSION}-SHA-256.txt.asc \
  && gpg --verify cmake-SHA-256.txt.asc \
  && sha256sum --ignore-missing --check cmake-SHA-256.txt \
  && tar -xzvf ${CMAKE_TARBALL} --directory=/opt/ \
  && ln -sfn /opt/cmake-${CMAKE_VERSION}-Linux-x86_64/bin/* /usr/bin \
  && rm -f ${CMAKE_TARBALL} cmake-*SHA-256.txt*

ENV PATH $PATH:/opt/cmake-3.21.3-linux-x86_64/bin

WORKDIR /root

RUN python -V && cmake --version && env

# TODO: set ENTRYPOINT