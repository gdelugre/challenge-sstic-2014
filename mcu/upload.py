#!/usr/bin/env python

import socket, select

#
# Microcontroller architecture is still undocumented.
#
# MEMORY MAP:
#
#   [0000-07FF] - Firmware
#   [0800-0FFF] - Unmapped
#   [1000-EFFF] - RAM
#   [F800-FBFF] - Protected memory area
#   [FC00-FCFF] - HW Registers
#   [FD00-FFFF] - ROM
#

FIRMWARE = "fw.hex"

print("---------------------------------------------")
print("----- Microcontroller firmware uploader -----")
print("---------------------------------------------")
print()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('91.121.41.47', 20000))

print(":: Serial port connected.")
print(":: Uploading firmware... ", end='')

[ s.send(line) for line in open(FIRMWARE, 'rb') ]

print("done.")
print()

resp = b''
while True:
    ready, _, _ = select.select([s], [], [], 10)
    if ready:
        data = s.recv(32)
        if not data:
            break
        resp += data
    else:
        break

print(resp.decode("utf-8"))
s.close()

