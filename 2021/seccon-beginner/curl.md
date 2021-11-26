# Check URL

Category: Web

> Have you ever used `curl`?

`index.php` provided:

```php
<?php
    error_reporting(0);
if ($_SERVER["REMOTE_ADDR"] === "127.0.0.1"){
    echo "Hi, Admin or SSSSRFer<br>";
    echo "********************FLAG********************";
}else{
    echo "Here, take this<br>";
    $url = $_GET["url"];
    if ($url !== "https://www.example.com"){
        $url = preg_replace("/[^a-zA-Z0-9\/:]+/u", "👻", $url); //Super sanitizing
    }
    if(stripos($url,"localhost") !== false || stripos($url,"apache") !== false){
        die("do not hack me!");
    }
    echo "URL: ".$url."<br>";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 2000);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    echo "<iframe srcdoc='";
    curl_exec($ch);
    echo "' width='750' height='500'></iframe>";
    curl_close($ch);
}
?>
```

Basically, the code takes in a URL, fetches it using `cURL` and returns the contents. To get the flag, we must somehow send a HTTP request to the page from `127.0.0.1`, which is the local loopback address (aka localhost).

However, exploiting this app is not as simple as entering `localhost`, because there are several checks in place. Let's look at each of them:

1. ```php
   $url = preg_replace("/[^a-zA-Z0-9\/:]+/u", "👻", $url);
   ```

   This regex replaces everything that's not a letter, digit, `/` or `:` with 👻. This means our URL cannot contain dots, which is a major problem

2. ```php
   if(stripos($url,"localhost") !== false || stripos($url,"apache") !== false){
       die("do not hack me!");
   }
   ```

   Entering `localhost` anywhere in the URL fails. Not sure what the apache one is for.

So how to send a request to localhost without using `localhost` or `127.0.0.1`? Luckily, [cURL supports a bunch of IP address formats](https://daniel.haxx.se/blog/2021/04/19/curl-those-funny-ipv4-addresses/), including the hex encoded format.

IPv4 addresses can be represented in the form of a 32 bit integer, as they are essentially made up of 4 bytes. Here's a short program to convert a regular IP address to hex form:

```python
def to_hex(addr):
	return "0x"+"".join([hex(int(x))[2:].zfill(2) for x in addr.split(".")])
>>> to_hex("127.0.0.1")
'0x7f000001'
```

Thus, when we go to `https://check-url.quals.beginners.seccon.jp/?url=0x7f000001`, the app makes a request to `127.0.0.1`, giving us the flag!

`Flag: ctf4b{5555rf_15_53rv3r_51d3_5up3r_54n171z3d_r3qu357_f0r63ry}`

