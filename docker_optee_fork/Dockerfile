FROM ubuntu:18.04
MAINTAINER Joakim Bech (joakim.bech@linaro.org)

# This is needed on later Ubuntu distros to be able to install the i386
# packages.
RUN dpkg --add-architecture i386

RUN apt-get update && apt-get install -y --force-yes \
    android-tools-adb \
    android-tools-fastboot \
    autoconf \
    bc \
    bison \
    ccache \
    cscope \
    curl \
    flex \
    gdisk \
    git \
    iasl \
    libattr1-dev \
    libcap-dev \
    libc6:i386 \
    libfdt-dev \
    libftdi-dev \
    libglib2.0-dev \
    libhidapi-dev \
    libncurses5-dev \
    libpixman-1-dev \
    libpython2.7 \
    libstdc++6:i386 \
    libtool \
    libz1:i386 \
    make \
    mtools \
    netcat \
    python \
    python3-pip \
    python3-numpy \
    python3-pyelftools \
    tmux \
    unzip \
    uuid-dev \
    xdg-utils \
    xterm \
    xz-utils \
    vim \
    zlib1g-dev \
    libssl-dev \
    wget \
    cpio \
    rsync

# Download repo
RUN curl https://storage.googleapis.com/git-repo-downloads/repo > /bin/repo
RUN chmod a+x /bin/repo

RUN useradd --create-home --shell /bin/bash optee
RUN echo 'root:root' | chpasswd
RUN echo 'optee:optee' | chpasswd

USER optee

# Configure git so repo won't complain later on
RUN git config --global user.name "OP-TEE"
RUN git config --global user.email "op-tee@linaro.org"

RUN pip3 install pyserial Wand pycrypto pycryptodomex

RUN mkdir -p /home/optee/qemu-optee
RUN mkdir -p /home/optee/bin
RUN mkdir -p /home/optee/.repo/manifests
WORKDIR /home/optee/qemu-optee

COPY --chown=optee qemu_v8.xml .

RUN /bin/repo init -m $PWD/qemu_v8.xml
RUN /bin/repo sync --no-clone-bundle

WORKDIR /home/optee/qemu-optee/build

RUN make toolchains
RUN echo "PATH=\$PATH:/home/optee/qemu-optee/toolchains/aarch64/bin:/home/optee/qemu-optee/toolchains/aarch32/bin" >> ~/.bashrc
RUN make CFG_DEVICE_ATTESTATION=y CFG_THIRD_PARTY_TA=y 2>&1 | tee build.log

WORKDIR /home/optee

VOLUME qemu-optee

# RUN make QEMU_VIRTFS_ENABLE=y QEMU_VIRTFS_HOST_DIR=/home/optee/bin run-only
