#!/usr/bin/env zsh

adb -s 0149BCA901007012 ls /data/local/tmp
adb -s 0149BCA901007012 push ../sstic14-armecage /data/local/tmp/badbios.bin
adb -s 0149BCA901007012 ls /data/local/tmp
adb -s 0149BCA901007012 shell chmod +x /data/local/tmp/badbios.bin
