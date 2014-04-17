#!/bin/sh

if [[ $EUID -ne 0 ]]; then
    echo "Must be run as root." 1>&2
    exit 1
fi

adb -s 8113b63c shell rm -f /data/local/tmp/badbios.bin
modprobe usbmon
usbmon -fu -s 8192 > usbmon.trace &

adb -s 8113b63c ls /sdcard/
adb -s 8113b63c ls /sdcard/Documents/
adb -s 8113b63c ls /data/local/tmp

echo "...Move your mouse..."
sleep 2

adb -s 8113b63c push $1 /data/local/tmp/badbios.bin
adb -s 8113b63c ls /data/local/tmp

sync
pkill usbmon

verify_file=$(mktemp -u)
ruby extract_bin.rb usbmon.trace $verify_file
md5sum $1
md5sum $verify_file
rm -f $verify_file

cat HELP.txt usbmon.trace | xz > usbtrace.xz
