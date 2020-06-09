#!/bin/bash

if [[ "$1" == "-h" ]]; then
    echo "Usage: $0 [-ht]"
    echo -e "\th: display help menu"
    echo -e "\tt: compile OP-TEE test suite"
else
    cd
    export PATH=$PATH:/home/optee/qemu-optee/toolchains/aarch64/bin:/home/optee/qemu-optee/toolchains/aarch32/bin
    export CROSS_COMPILE="ccache aarch64-linux-gnu-"

    OPTEE_VER=3.8.0
    TF_VER=v2.2
    UBOOT_VER=v2020.04-rc3
    LINUX_VER=v5.6

    git clone https://review.trustedfirmware.org/TF-A/trusted-firmware-a -b $TF_VER --depth=1
    git clone https://github.com/u-boot/u-boot.git -b $UBOOT_VER --depth=1
    git clone https://github.com/OP-TEE/optee_os.git -b $OPTEE_VER --depth=1
    git clone https://github.com/OP-TEE/optee_client -b $OPTEE_VER --depth=1
    git clone https://github.com/torvalds/linux.git -b $LINUX_VER --depth=1
    
    cd trusted-firmware-a
    make PLAT=sun50i_a64 SPD=opteed DEBUG=1 bl31
    export BL31=$(pwd)/build/sun50i_a64/debug/bl31.bin


    cd ../optee_os
    make CFG_ARM64_CORE=y \
         CFG_TEE_LOGLEVEL=4 \
         CFG_TEE_CORE_LOG_LEVEL=4 \
         CROSS_COMPILE32="ccache arm-linux-gnueabihf-" \
         CROSS_COMPILE64="ccache aarch64-linux-gnu-" \
         DEBUG=1 \
         PLATFORM=sunxi-sun50i_a64
    export TEE=$(pwd)/out/arm-plat-sunxi/core/tee.bin
    export DEV_KIT_DIR=$(pwd)/out/arm-plat-sunxi/export-ta-arm64

    cd ../u-boot
    make pine64_plus_defconfig O=tmp
    make O=tmp

    cd ../optee_client
    make
    cd out/export
    export TEEC=$(pwd)/usr


    cd ../linux
    make ARCH=arm64 defconfig
    make -j2 ARCH=arm64 Image
    make -j2 ARCH=arm64 dtbs
    make -j2 ARCH=arm64 modules
    make -j2 ARCH=arm64 INSTALL_MOD_PATH=modules modules modules_install
    
    if [[ "$#" -eq 1 && "$1" == "-t" ]]; then
        git clone https://github.com/linaro-swg/optee_examples.git -b $OPTEE_VER
        cd optee_examples/hello_world/host
        make --no-builtin-variables
        cd ../ta
        make PLATFORM=sunxi-sun50i_a64 TA_DEV_KIT_DIR=$DEV_KIT_DIR
        echo "Hello world TA built!"
    fi
    
    tar -cfv optee_client.tar.gz usr
fi
