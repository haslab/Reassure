#!/bin/bash
SRC_DIR=$(pwd)
PATH=$PATH:$HOME/qemu-optee/toolchains/aarch32/bin:$HOME/qemu-optee/toolchains/aarch64/bin/

cd $HOME/qemu-optee/optee_client
make CROSS_COMPILE=aarch64-linux-gnu-

cd $SRC_DIR
make TA_DEV_KIT_DIR=$HOME/qemu-optee/optee_os/out/arm/export-ta_arm64 \
     clean

make CROSS_COMPILE=aarch64-linux-gnu- \
     TEEC_EXPORT=$HOME/qemu-optee/optee_client/out/export/usr \
     TA_DEV_KIT_DIR=$HOME/qemu-optee/optee_os/out/arm/export-ta_arm64

cp host/sign_ecdsa_client ta/*.ta $HOME/bin
