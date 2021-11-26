# Command Injection 5

* **Category:** Web
* **Points:** 496

## Challenge
```
MAMAAAAAAAAAAAAAAA. LIFE HAS JUST BEGANNNNNNNNNNNNNNNNNNNNNNNNNNNNN. THERE WILL BE NO MORE COMMAND INJECTIONS TOMORROW......... CARRY ONNNNNNNN CARRY ONNNNNNNNNNN. DA DA DA DA DA DADA DAAAAAAAAAAAAAAAAAAAAA

http://157.245.202.4:1341

Flag format: flag{.+}

Challenge by: Gladiator
```
## Solution
From the source, the only difference from Command Injection 4 is the addition of more filters on the output.  
The list of filtered input is still the same. The changes do not really affect my payload from the previous challenge, except changing from hex to octal, as `f` is forbidden.  
The approach described should work for Command Injection 3-5.

### Vulnerabilities from Command Injection 3
The web app uses [`strpos`](https://www.php.net/manual/en/function.strpos.php) to validate input.
```php
if(strpos($cmd, $value)){
   echo "HACKER!";
   die();
}
```
A warning can be found in the PHP docs:

> **Warning**  
  This function may return Boolean FALSE, but may also return a non-Boolean value which evaluates to FALSE. Please read the section on Booleans for more information. Use the === operator for testing the return value of this function.

> Returns FALSE if the needle was not found.

This means that `strpos("hello","h") == strpos("hello",z") == false`. This is crucial, as the first command is effectively exempt from filtering.  
Another thing to note is although the string `flag` is banned, we can still use [file globbing](https://www.geeksforgeeks.org/file-globbing-linux/) to reference the flag file.

**Payload:** `cat /f*/*`  
**Flag:** `flag{aint_no_wafu_like_youuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu}`

### Vulnerabilities from Command injection 4
Our file globbing trick from the previous challenge no longer works as individual characters of the word `flag` are banned.  
We also cannot read the file in plain text, because `_` is banned in the output.  

We can overcome the first obstacle with knowledge of the flag file location: `cat /????/????.t?t`   
The second obstacle is slightly harder. We have to use [od](https://www.geeksforgeeks.org/od-command-linux-example/) (octal dump) to encode the flag.  

**Payload**: `od -b -An /????/????.t?t`  
**Flag**: 


Hmm, no output. I realized that the flag location had been changed.  
We have to use `ls` to find the flag file. Fortunately, `ls` starts with `l`, so we can use that anywhere in our payload.

**Payload**: `ls /?l??`   
**Output**: `secrets`

Let's hope the flag is in this new directory  

**Payload**: `od -b -An /????/secre*/????.t?t`  
**Flag**: `flag{MAMAAAAAAAAAAAAAAAAAAAAAAA_Just_killed_a_mannnnnnnn}`
  
Note: Output needs to be [converted](http://www.unit-conversion.info/texttools/octal/#data) from octal to text.

### Command injection 5
The payload is the same as the previous challenge  
**Flag**: `flag{why_cant_you_just_spell_my_IGN_instead_Gladiator_is_back}`