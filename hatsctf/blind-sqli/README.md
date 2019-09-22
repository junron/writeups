# Blind Sql

* **Category:** Web
* **Points:** 500

## Challenge
```
Blind SQL. CAN YOU DO IT??!??!?!

NOTE: DB is SQLite
NOTE: I FORGOT TO CHANGE THE HTML VISUALS. IT SAYS UNION BUT IT IS BLIND!

http://157.245.202.4:1355/

Have fun.

Challenge by: Gladiator
```
## Investigation
As the challenge title states, it is a blind SQL injection challenge.  
That means we are limited in the data we can extract with each request.
The previous query doesn't give us the flag:
> Query: `and 0 union select flag,"bleh" from flag;--`  
 Output: `Wakanda`

But the output is interesting.    
Let's see what happens if we select no rows.
> Query: `and 0;--`  
 Output: 

There is no output. This confirms that the challenge is a blind SQL injection: we only know if there is output or not.

Armed with this knowledge, we can run some comparision operations to find out information about the flag.
First, let's check that the flag is where we expect it to be:
> Query: `' or (select count(flag) from flag)>0;--`  
 Output: `Wakanda`

This shows that there is at least 1 row in the `flag` column in the `flag` table. That's probably where our flag is.

Next, we will find the length of the flag to see which approach we should take to obtain the flag.  
> Query: `' or (select length(flag) from flag) > n;--`  
 Output: `Wakanda`

We can use [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) to determine the length of the flag, by varying n.
We can do this manually as it will take less than 10 queries. The flag is 85 characters, which is quite long.

## Getting the flag
We can use binary search to obtain the characters in the flag.
By varying `<char>` in the query below, we can determine each character of the flag relatively quickly.
> Query: `' or substr((select flag from flag),1,1)>"<char>";--`

A quick calculation shows that it would take `7*85 = 595`<sup>1</sup> requests to find the flag, even using binary search, which is far too long to do in series.  
Instead, I used kotlin to parallelize the queries and do binary search on all the characters at once.  
The kotlin script can be found [here](src/main/kotlin/exploit.kt).

Running requests in parallel is much faster, yielding the flag in less than a minute.

## Flag
`HATS{you_dont_need_me_but_i_need_you_web_you_are_my_my_my_my_my_my_my_lover_yeet}`



##### Notes:
<sup>1</sup>Binary search requires log<sub>2</sub>(n) comparisons for a set of n possibilities. For ASCII characters, n = 128, log<sub>2</sub>(128) = 7.  
Note that this is much faster than brute forcing the flag, which requires 128<sup>85</sup> guesses.
