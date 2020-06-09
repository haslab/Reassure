#!/bin/bash
SRC=qds_attest

cp $SRC.c ~/qemu-optee/optee_os/core/pta/

if [[ ! $(grep $SRC.c ~/qemu-optee/optee_os/core/pta/sub.mk) ]]; then
    echo "srcs-\$(CFG_DEVICE_ATTESTATION) += $SRC.c" >> ~/qemu-optee/optee_os/core/pta/sub.mk
fi

cp $SRC.h ~/qemu-optee/optee_os/lib/libutee/include/

cd ~/qemu-optee/build && make CFG_DEVICE_ATTESTATION=y -j2 all
