# BabyPHP

### burden_bear

**Category: Web**

> John is trying to juggle between learning PHP and his other homework. Fortunately, he managed to complete his PHP task - creating a simple web login. He challenges you to find a way to bypass his login.
>
> Take a look at his PHP masterpiece now! [chals.whitehacks.ctf.sg:50201](http://chals.whitehacks.ctf.sg:50201/)

Flag: `WH2021{H0p3d_u_h4d_f4n_juGGl15g}`

There are multiple parts to this challenge, let's look at it part by part.

## Part 1:

```php
$t = $_GET['ticket'];

if ($t !== base64_encode("ILuvWH2021")) {
    die("Do you hate us?");
}
```

The code checks that the `ticket` HTTP parameter is equal to the [base64 encoded]([Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)) version of `ILuvWH2021`, which is `SUx1dldIMjAyMQ==`

## Part 2:

```php
$c1 = $_GET['code1'];
$c2 = $_GET['code2'];
if(!isset($c1) || !isset($c2)) {
    die("Is that all you got?");
}

if(md5($c1) != 0 || $c2 != sha1($c2)) {
    die("Try harder!");
}
```

The second part is a bit more challenging. It is widely known that ~~php sucks~~ php suffers from a range of vulnerabilities, but [magic hashes]([Magic Hashes | WhiteHat Security](https://www.whitehatsec.com/blog/magic-hashes/)) is less well known.

#### Part 1.1: Type juggling

PHP's equality checks can be very surprising, due to its support for type juggling. Let's look at an example:

```php
echo 11 == "11ctf"; // True (11==11)
echo 0 == "0e11"; // True (0==0)
echo "0e12" == "0e11"; // True
```

Interestingly, all of the above comparisons are True. 

When the two values being compared are of different types, such as int and string in example 1 and 2, PHP coerces the string to an int and compares them.

Example 3 is a lot more interesting. `"0e12"` and `"0e11"` are clearly strings, that are clearly not equal. Well, PHP interprets a string starting  with `[x]e` followed by digits as $x\cdot 10 ^{\text{digits}}$. For example, `"2e6"==2000000` (2 million). 

While `"0e12"` and `"0e11"` are clearly not equal, $0\cdot10^{12}=0\cdot10^{13}=0$. 

Read more: [here](https://news.ycombinator.com/item?id=9484757)

#### Part 1.2: Hashing

The output of hash algorithms, like MD5, is usually a hex string, containing characters `[0-9][a-f]` like `de28a20d12beef`. 

(Un)fortunately, `0e` is a valid hex string that could be produced by a hash algorithm. Although the bytes after `0e` are random hex characters, when PHP compares the hashes, each hash evaluates to zero. 

While it may take a while to generate these hashes, someone has kindly put together a [repo](https://github.com/spaze/hashes) of strings that produce hashes starting with `0e`.

#### Part 1.3: Putting it together

Let's look at this code snippet in more detail.

```php
if(md5($c1) != 0 || $c2 != sha1($c2)) {
    die("Try harder!");
}
```

Firstly, we will need to find a string whose MD5 hash is equal to zero (in PHP). There are plenty of strings to choose from, we can choose `NOOPCJF`.

Secondly, we need to find a string whose SHA1 hash is equal to itself. This is a special condition as both the string and its hash must start with `0e`. Fortunately, there are still a bunch of them in the repo, such as `0e01010111000111111010101011010111010100`.

## Part 3:

```php
$c3 = $_GET['code3'];
if (!isset($c3) || $c3 === $c1 || $c3 != 0 || md5($c3) != md5($c1)) {
    die("Try harrrrderrrr.");
}
```

This part is quite similar to part 2. We need to find a string, not equal to the strings in part 2, whose MD5 hash is equal to the hash of the previous string, which is zero as we have found out earlier. We can pick another string from the md5 file in the repo, such as `GZECLQZ`.

## Part 4: 

I was stuck for a really long time on this part. I went to solve other challenges before coming back to this. 

```php
$user = $_GET['username'];
$pass = $_GET['pass'];

// HA! Now its salted, see how you gonna get past it!
if ($user !== $pass && md5($user.$salt) === md5($pass.$salt)) {
    die($flag);
}
```

Now, we need to find two strings, whose hash when concatenated with a random value are equal. 

One obvious solution is `user==pass`, but the code checks for that. The other problem is that the code uses strict equality checking, which means our earlier `0e` exploits won't work. What can we do?

PHP's type juggling support not only affects equality, but also concatenation. This is a common feature in other weakly typed languages like JS: 

```js
"hello" + {}; // "hello[object Object]"
```

In node/Express web challenges, it is common to pass dictionaries/arrays in HTTP parameters to cause unexpected behavior in applications.

Perhaps we can apply the same technique to PHP?

After some googling, I found that we can indeed [pass arrays as parameters](https://stackoverflow.com/a/13389026/11168593) to PHP.

Let's see what happens when `$user` and `$pass` are arrays. It turns out in PHP, when an array is concatenated with a string, the result is `"Array" + string`, for example `array("A")+"List"==="ArrayList"`.

With this knowledge, we are now ready to put all the parts together to execute our attack.

## Putting it together

From part 1: 

`ticket=SUx1dldIMjAyMQ==`

From part 2:

`code1=NOOPCJF`

`code2=0e01010111000111111010101011010111010100`

From part 3:

`code3=0e215962017`

From part 4:

`username=1&username[]=1`

`pass=0&pass[]=0`

All together:

`chals.whitehacks.ctf.sg:50201/?ticket=SUx1dldIMjAyMQ==&code1=NOOPCJF&code2=0e01010111000111111010101011010111010100&code3=0e215962017&username=1&username[]=1&pass=0&pass[]=0`

## Comments

This challenge was something beyond the typical PHP magic hash challenges and I had to think about part 4 for a while. I also learnt about PHP type juggling when dealing with arrays, another technique that will go into my pentesting toolbox.