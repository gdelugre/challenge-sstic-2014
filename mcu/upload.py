#!/usr/bin/env python

import binascii, socket, struct

#FIRMWARE = b"\x00" * 512

fd = open('fw.bin', 'rb')
FIRMWARE = fd.read()
fd.close()

print("---------------------------------------------")
print("----- Microcontroller firmware uploader -----")
print("---------------------------------------------")
print()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 20000))

print(":: Serial port connected.")
print(":: Uploading firmware... ", end='')
s.send(struct.pack(">H", len(FIRMWARE)))
s.send(struct.pack(">I", binascii.crc32(FIRMWARE) & 0xffffffff))
s.send(FIRMWARE)
print("done.")
print()

resp = b''
while 1:
    c = s.recv(1)
    if not c:
        break
    if len(c) > 0:
        resp += c

print(resp.decode("utf-8"))
s.close()

