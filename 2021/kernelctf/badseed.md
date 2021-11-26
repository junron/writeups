# Badseed

Category: Kiddy pool

In this challenge, we are given a 64 bit linux binary.

```sh
$ file badseed       
badseed: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d1923d37cdc7c798e5d6294b0dca49ba75519fc9, for GNU/Linux 3.2.0, not stripped
```

Typically, linux binaries can appear in two different categories of challenges: pwn and reversing. In either case, the next course of action is to decompile the binary.

When a C program is compiled using `gcc` or any other compiler, source code is parsed and transformed into assembly instructions. These instructions are then encoded and packed together, along with some headers and metadata, to give you a compiled binary that your operating system can run.

Decompilation is the reverse process: we use special software to recover much of the source code from the binary file. Although the decompilation is not perfect, it allows us to get a better idea of what the binary is doing.

To decompile a C binary, you can use [ghidra](https://ghidra-sre.org/) (which is free and open source) or [IDA](https://hex-rays.com/ida-pro/) (which costs a ton of money). I'll be using ghidra, as it's much more accessible to a beginner. 

## Analysis

Once you've launched ghidra, you'll probably see an empty project. Drag the binary into the project window and double click it.

When the binary opens up, you will see the following message:

> badseed has not been analyzed. Would you like to analyze it now?

Click `Yes` and then click `Analyze`.

Type `main` into the filter in the `Symbol Tree` window and double click `main`.  The main function contains the code that will be run when the program starts.

You should see the following code pop up in a pane to the right:

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  init(param_1);
  question_one();
  question_two();
  question_three();
  gz();
  return 0;
}
```

From this decompilation, we can see that `main` calls an `init` function, three question functions and finally `gz`. We can now double click any of these functions to view their decompilation. I will skip the `init` function as it isn't very interesting.

### `question_one`

```c
void question_one(void)

{
  long in_FS_OFFSET;
  double dVar1;
  int local_24;
  float local_20;
  int local_1c;
  int local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_20 = 6.035077;
  local_1c = 4000;
  local_24 = 0;
  local_18 = 0;
  dVar1 = floor(6.035077095031738);
  local_14 = (int)dVar1;
  local_18 = (int)((float)local_1c / local_20);
  puts("how heavy is an asian elephant on the moon?");
  __isoc99_scanf(&DAT_00402034,&local_24);
  if (local_18 != local_24) {
    puts("wrong bye bye");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("\ngreat 2nd question:");
  puts("give me the rand() value");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

When we're analyzing programs, one of the first things to look out for are

1. How is the program getting its inputs?
2. What decisions is the program making?

In this function, `scanf` is called with format specifier `%d` (you can click on `DAT_00402034` to see that it points to `%d`) and the result is read into `local_24`. So the program expects an integer as input and stores it into `local_24`. Next, it compares `local_18` against `local_24`. If the two are not equal, the program exits (which is almost definitely a bad thing), but if they are equal, the program moves on to the second question (a good thing).

Now, we can move on to look at the value of `local_18`.  I've grabbed a few lines of code relevant to its computation:

```c
local_20 = 6.035077;
local_1c = 4000;
// Other code
local_18 = (int)((float)local_1c / local_20)
```

Ok that doesn't seem that complicated: it's just division of two numbers. Using python or a calculator, you will find that `floor(4000/6.035077)=662`. So if we enter 662, we can get to the next question!

### `question_two`

```c
void question_two(void)

{
  long in_FS_OFFSET;
  int local_24;
  int local_20;
  int local_1c;
  time_t local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = time((time_t *)0x0);
  __isoc99_scanf(&DAT_00402034,&local_24);
  srand((uint)local_18);
  local_20 = rand();
  local_1c = rand();
  if (local_1c != local_24) {
    puts("wrong bye bye");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("great 3rd question:");
  puts("no hint this time... you can do it?!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

In this challenge the input is also an integer, as we see the `scanf` into `local_24` again. `local_24` is compared against `local_1c`, which is the return value of the `rand` function. Searching "rand function C" on google, we find that [the `rand` function returns a pseudo-random number](https://www.tutorialspoint.com/c_standard_library/c_function_rand.htm). Wait, random number? How do we predict that?

Scrolling down a bit, there's an example usage of the `rand` function:

```c
/* Intializes random number generator */
srand((unsigned) time(&t));

/* Print 5 random numbers from 0 to 49 */
for( i = 0 ; i < n ; i++ ) {
	printf("%d\n", rand() % 50);
}
```

Hmm, the `srand` and `time` functions are called in our binary too! The [`srand` function sets the RNG's seed](https://www.tutorialspoint.com/c_standard_library/c_function_srand.htm) and the [`time` function returns the current time](https://www.geeksforgeeks.org/time-function-in-c/). Since the return value of the `time` function is passed to the `srand` function, the RNG seed is actually the current time, which we can predict!

The only problem is, we'd have to generate a random number and type it in at exact moment of time when the program is run, which is almost impossible. Luckily, we can use an amazing library called [pwntools](https://docs.pwntools.com/) to automate this process with the precision of a machine. Pwntools is incredibly useful for a huge range of things, from binary exploitation, to reversing and even solving interactive crypto challenges.

To generate random numbers, I made this small C program that replicates what the binary is doing:

```c
#include <stdio.h>
#include <stdlib.h>
int main(){
    srand(time(NULL));
    int x = rand();
    int y = rand();
    printf("%d\n",y);
    return 0;
}
```

Note that the binary calls `rand` twice, but only uses the second one. I compiled the C program into a binary called `random`.

Now, we can write some python code to automate solving question 2:

```python
# Import all functions from pwntools
from pwn import *

# Start the challenge binary as a process
# By storing it in a variable, we can send inputs to it and receive its output
p = process("./badseed")

# Uncomment this line to send inputs to the challenge server instead 
# p = remote("ctf.k3rn3l4rmy.com", 2200)

# We use the sendline function to send input to the process
# This is the value from question 1
p.sendline("662")
# We then start our random number generator process
r = process("./random")
# And read its output to obtain the random number
# Remember to use the int function, as the output is returned as a string
x = int(r.recvline())
# Send the predicted random number to the challenge process
p.sendline(str(x))
# We use the interactive function to allow us to interact with the process
# through the terminal, instead of through pwntools
p.interactive()
```

You will need to install pwntools to run this code. 

You should see this output:

```sh
$ python3 badseed.py
[+] Starting local process './badseed': pid 2879
[+] Starting local process './random': pid 2881
[*] Process './random' stopped with exit code 0 (pid 2881)
[*] Switching to interactive mode
how heavy is an asian elephant on the moon?

great 2nd question:
give me the rand() value
great 3rd question:
no hint this time... you can do it?!
$  
```

### `question_three`

```c
void question_three(void)

{
  long in_FS_OFFSET;
  int local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  time_t local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = time((time_t *)0x0);
  srand((uint)local_18);
  local_28 = rand();
  srand(local_28);
  local_24 = rand();
  local_20 = (int)local_28 / local_24;
  local_1c = local_20 % 1000;
  __isoc99_scanf(&DAT_00402034,&local_2c);
  if (local_1c != local_2c) {
    puts("wrong bye bye");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("great heres your shell");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

In this part, we see `rand`, `srand` and `time` again. Interestingly, `srand` is called twice, once with the current time, and again with the first output of `rand`. The final output is the ratio of the first `rand` output to the second, modulo 1000. It's no big deal, and we'll use the same technique from the previous part, accounting for these new tweaks.

I wrote a new C program:

```c
#include <stdio.h>
#include <stdlib.h>
int main(){
    srand(time(NULL));
    int x = rand();
    srand(x);
    int y = rand();
    printf("%d\n",(x/y)%1000);
    return 0;
}
```

and compiled it into `random2`.

Next, I copied the python code for part 2 and changed the process name, giving me this script:

```python
# Import all functions from pwntools
from pwn import *

# Start the challenge binary as a process
# By storing it in a variable, we can send inputs to it and receive its output
p = process("./badseed")

# Uncomment this line to send inputs to the challenge server instead 
# p = remote("ctf.k3rn3l4rmy.com", 2200)

# We use the sendline function to send input to the process
# This is the value from question 1
p.sendline("662")

# We then start our random number generator process
r = process("./random")
# And read its output to obtain the random number
# Remember to use the int function, as the output is returned as a string
x = int(r.recvline())
# Send the predicted random number to the challenge process
p.sendline(str(x))

# Basically the same as part 2, with a different process name
r = process("./random2")
x = int(r.recvline())
p.sendline(str(x))

# We use the interactive function to allow us to interact with the process
# through the terminal, instead of through pwntools
p.interactive()
```

And when we run the script again, we get our shell:

```sh
$ python3 badseed.py
[+] Starting local process './badseed': pid 3047
[+] Starting local process './random': pid 3049
[*] Process './random' stopped with exit code 0 (pid 3049)
[+] Starting local process './random2': pid 3051
[*] Process './random2' stopped with exit code 0 (pid 3051)
[*] Switching to interactive mode
how heavy is an asian elephant on the moon?

great 2nd question:
give me the rand() value
great 3rd question:
no hint this time... you can do it?!
great heres your shell
$ whoami
kali
$  
```

Yay!

All that's left is to uncomment the 9th line to run the script on the challenge server instead of our local binary. If this script doesn't work on the challenge server, your system clocks might be out of sync. You can try using NTP to sync your clocks. Or the admins might have taken the challenge server down.



## Flag

> flag{i_0_w1th_pwn70ols_i5_3a5y}

Indeed it is