#!/usr/bin/env python

import socket, select
import binascii, random, array

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

def fuzz(line):
    if len(line) == 11:
        return line
    header = [c for c in binascii.unhexlify(line[1:9])]
    data = binascii.unhexlify(line[9:-3])
    fuzzed = [ c ^ (random.randint(0,0xff) if random.random() > 0.8 else 0) for c in data ]
    crc = [ (-sum(header + fuzzed)) & 0xff ]
    return line[0:9] + binascii.hexlify(array.array('B', fuzzed + crc).tostring()).upper() + b'\n'

print("---------------------------------------------")
print("----- Microcontroller firmware uploader -----")
print("---------------------------------------------")
print()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 20000))

print(":: Serial port connected.")
print(":: Uploading firmware... ", end='')

[ s.send(fuzz(line)) for line in open(FIRMWARE, 'rb') ]

print("done.")
print()

resp = b''
while True:
    ready, _, _ = select.select([s], [], [], 10)
    if ready:
        try:
            data = s.recv(32)
        except:
            break
        if not data:
            break
        resp += data
    else:
        break

print(resp.decode("utf-8"))
s.close()

