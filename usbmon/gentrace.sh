#!/bin/sh

if [[ $EUID -ne 0 ]]; then
    echo "Must be run as root." 1>&2
    exit 1
fi

adb -s 8113b63c shell rm -f /data/local/tmp/badbios.bin
modprobe usbmon
usbmon -fu -s 8192 > usbmon.trace &

adb -s 8113b63c shell id
adb -s 8113b63c shell uname -a

adb -s 8113b63c ls /sdcard/
adb -s 8113b63c ls /sdcard/Documents/
adb -s 8113b63c ls /data/local/tmp

echo "...Move your mouse..."
sleep 2

adb -s 8113b63c push $1 /data/local/tmp/badbios.bin
adb -s 8113b63c shell chmod 777 /data/local/tmp/badbios.bin
adb -s 8113b63c ls /data/local/tmp

sync
pkill usbmon

# Patch uname output
sed -i -e 's/^\(.* =\) 4c696e75.*/\1 4c696e75 78206c6f 63616c68 6f737420 342e312e 302d6734 65393732 65652023 3120534d 50205052 45454d50 54204d6f 6e204665 62203234 2032313a 31363a34 30205053 54203230 31352061 726d7638 6c20474e 552f4c69 6e7578/g' usbmon.trace

verify_file=$(mktemp -u)
ruby extract_bin.rb usbmon.trace $verify_file
md5sum $1
md5sum $verify_file
rm -f $verify_file

cat HELP.txt usbmon.trace | xz > usbtrace.xz
