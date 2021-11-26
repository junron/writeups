# Extremely Complex Challenge

Category: Crypto

Points: 458

> Eric has an elliptic curve defined over a Galois field with order 404993569381. A generator point (391109997465, 167359562362) is given along with a public key (209038982304, 168517698208). We also know that the curve is defined as y^2 = x^3 + ax + b (mod p), and that b is equal to 54575449882. What is Eric’s private key?
>
> Express the key as an integer in base 10. Use the flag format flag{+private_key+}.
>
> Author: AC

This is an elliptic curve question. Elliptic curves are defined by the equation `y^2 = x^3 +ax + b​` over a finite field. 

In ECC, the public key is `P = nG​` where `G` is the public generator or base point and `n​` the private key (an integer). The process of obtaining `n` from `P` is hard and is known as the Elliptic Curve Discrete Logarithm Problem (ECDLP). Fortunately, there are a few attacks we can use to make the process easier.

The first step is to find `a` , which can be easily solved using [Wolfram Alpha]([https://www.wolframalpha.com/input/?i=solve+167359562362%5E2+%3D+391109997465%5E3+%2B+a*391109997465+%2B+54575449882+mod+404993569381](https://www.wolframalpha.com/input/?i=solve+167359562362^2+%3D+391109997465^3+%2B+a*391109997465+%2B+54575449882+mod+404993569381)).

```
a = 316508952642
```

One attack we can use is the Pollard-rho attack, described [here](https://github.com/diogoaj/ctf-writeups/tree/master/2017/picoctf/cryptography/ECC2-200) and [here](https://hgarrereyn.gitbooks.io/th3g3ntl3man-ctf-writeups/2017/picoCTF_2017/problems/cryptography/ECC2/ECC2.html). I ~~have no idea~~ do not completely understand what this attack does. I think it's similar to the [attack for DLP](https://crypto.stackexchange.com/questions/33434/how-to-compute-the-discrete-logarithm-of-diffie-hellman-with-a-composite-modulus?rq=1) for composite modulus.

Basically, we can reduce the problem to computing the discrete log for each of the factors of the order of the base point (I'm not sure what that is)

Anyway, the order of the base point can be easily factored using sage:

```python
factor(base.order()) # 2^2 * 19 * 16829 * 39581
```

We can then compute the discrete log of each of the factors:

```python
primes = [4, 19, 16829, 39581]
dlogs = []
for fac in primes:
    t = int(int(base.order()) / int(fac))
    dlog = discrete_log(t*pub,t*base,operation="+")
    dlogs += [dlog]
    print("factor: "+str(fac)+", Discrete Log: "+str(dlog))

# output
# factor: 4, Discrete Log: 1
# factor: 19, Discrete Log: 12
# factor: 16829, Discrete Log: 12436
# factor: 39581, Discrete Log: 18121
```

And now we can ***magically*** combine the results using CRT:

```python
n = crt(dlogs,primes)
print("Private key:", n) # Private key: 17683067357
print("Verify:",n * base == pub) # True
```

Whoa we have magically obtained the private key! 

[script](ecc.sage)

Flag: `flag{17683067357}`