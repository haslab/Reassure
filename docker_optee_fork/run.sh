#!/bin/bash

echo "Reminder: Xquartz should be running (pref. settings: allow net. clients)"

IP=$(ifconfig | grep -e inet | grep -v '127.0.0.1' | awk '$1=="inet" {print $2}')
DISPLAY=$IP:0

#run xhost in xquartz bash
xhost + $IP

docker run -ti \
	   -e DISPLAY=$DISPLAY \
       --rm \
       -v /tmp/.X11-unix:/tmp/.X11-unix \
	   optee

#docker start optee
#docker attach optee

#If the IP is different run in the container 
# DISPLAY=IP
