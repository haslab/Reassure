#!/bin/bash


if [ $# -lt 1 ]; then
    echo "Usage:" $0 " source_dir"
else
    echo "Reminder: Xquartz should be running (pref. settings: allow net. clients)"
    IP=$(ifconfig | grep -e inet | grep -v '127.0.0.1' | awk '$1=="inet" {print $2}' | head -n 1)
    DISPLAY=$IP:0

    #run xhost in xquartz bash
    xhost + $IP

    docker run -ti \
           -e DISPLAY=$DISPLAY \
           --rm \
           -v /tmp/.X11-unix:/tmp/.X11-unix \
           -v $(pwd)/$1:/home/optee/mnt \
           optee_dev
fi
