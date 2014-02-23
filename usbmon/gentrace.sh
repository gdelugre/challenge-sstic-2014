#!/bin/sh

adb -s BH90EKK806 shell rm -f /data/local/tmp/badbios.bin
usbmon -fu -s 8192 > usbmon.trace &

adb -s BH90EKK806 ls /data/local/tmp
adb -s BH90EKK806 push $1 /data/local/tmp/badbios.bin
adb -s BH90EKK806 ls /data/local/tmp

sync
pkill usbmon

verify_file=$(mktemp -u)
ruby extract_bin.rb usbmon.trace $verify_file
md5sum $1
md5sum $verify_file
rm -f $verify_file
