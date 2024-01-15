#!/bin/sh
export PUNCH_TCP_LOCAL_ADDR=`netstat -ntp | grep $PPID | grep "$WEBSOCAT_CLIENT" | awk '{print $4;}' | head -1`
/raw
