#!/usr/bin/env python

import binascii, socket, struct

#
# MEMORY MAP:
#
#   [0000-07FF] - Firmware
#   [0800-0FFF] - Unmapped
#   [1000-EFFF] - RAM
#   [F800-FBFF] - Secret memory area
#   [FC00-FCFF] - HW Registers
#   [FD00-FFFF] - ROM
#

FIRMWARE = "fw.hex"

print("---------------------------------------------")
print("----- Microcontroller firmware uploader -----")
print("---------------------------------------------")
print()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 20000))

print(":: Serial port connected.")
print(":: Uploading firmware... ", end='')

[ s.send(line) for line in open(FIRMWARE, 'rb') ]

print("done.")
print()

resp = b''
while True:
    try:
        c = s.recv(1)
    except:
        break
    if not c:
        break
    if len(c) > 0:
        resp += c

print(resp.decode("utf-8"))
s.close()

