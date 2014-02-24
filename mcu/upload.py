#!/usr/bin/env python

import binascii, socket, struct

FIRMWARE = b"\x00" * 512

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

data = s.recv(4096)
print(data.decode("utf-8"))
s.close()

