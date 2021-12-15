# X marks Louis's treasure

### burden_bear

**Category: Web**

> Finding a web page that leads to Louis' hidden treasure on his server HEHEHEHE
>
>  [chals.whitehacks.ctf.sg:50101](http://chals.whitehacks.ctf.sg:50101/)

The login page hints at some kind of SQL injection attack, but basic attacks don't seem to yield any results. Looking at the source code, we find a HTML comment: 

```html
<!-- Or is it here in <img src="./cc665cc8baf65ba4f4b28dafdc3cf5a7/da4446ea44be23905b233381e45dd1f1/"-->
```

Accessing that link and inspecting element again yields another comment:

```html
<!--<a href="../secret.html"></a>-->
```

Secret.html contains yet another comment:

```html
<!--Wanna see more? Figure out where you should go? be a DIR-ean LISTer-->
```

I figured the challenge required listing the `./cc665cc8baf65ba4f4b28dafdc3cf5a7` directory, so I let [`dirb`](https://tools.kali.org/web-applications/dirb) run on the URL while looking at other challenges. However I later realized that directory listings were enabled on `./cc665cc8baf65ba4f4b28dafdc3cf5a7` so using dirb was unnecessary. 

Viewing the directory listing reveals a few interesting files:

- `upload.php`
- `uploads/user.xml`

`upload.php` features a file upload form, while `user.xml` has the following contents:

```xml
<root>
    <username>l0j0</username>
    <password>super_secr3t</password>
</root>
```

It is thus likely that this app is vulnerable to [XXE](https://portswigger.net/web-security/xxe). To verify this, we can try reading `/etc/passwd`

```xml-dtd
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
    <username>l0j0</username>
    <password>&xxe;</password>
</root>
```

Great! A list of users is returned in the password field.

Now, we can try changing the file path to obtain the flag. However, this error is returned: `failed to load external entity "file:///flag.txt" in **/var/www/app/cc665cc8baf65ba4f4b28dafdc3cf5a7/upload.php** on line **15**`. We can try to read the source code of `upload.php` for some clues. However, we cannot simply read the code as it will be executed by the PHP engine when it is injected into the page, so we have to encode it. Fortunately,  we can use the `php://filter` feature to encode files for us. 

```xml-dtd
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/app/cc665cc8baf65ba4f4b28dafdc3cf5a7/upload.php"> ]>
```

Decoding the base64, we find the following comment:

```html
<!-- You won't believe it, but the flag is in /home/l0j0/flag.txt - you'll never get it though! -->
```

Note: This comment can also be found by HTML inspecting the page :<

Setting the XXE path to `/home/l0j0/flag.txt` reveals the flag: `WH2021{th3_sup3r_s3cr3t_tr34sur3!}`

