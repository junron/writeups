# Cross site request forgery

If we can trick a user into loading a page, we can send requests with their credentials and cookie (hopefully)

However, this is clearly bad, so browsers and websites have implemented precautions against this.

## CORS (cross origin resource sharing)

When javascript sends a HTTP request to other sites, CORS prevents JavaScript from reading the response body.

This is fine if the response body is unimportant.

We can bypass this using a form POST, since forms are not JavaScript, thus are exempt from CORS.

We can send arbitrary data using `enctype=text/html` . However, we cannot obtain the response body. Fortunately, we can use `target=<iframeID>` to render the response in an iframe and thus execute any code the server sends.

We can also use script tags to include API responses that look like JS/we can manipulate to return something that looks like JS

## SameSite cookie

This is quite secure. SameSite=lax (the default) blocks sending cookies on cross origin requests. There is currently no way to bypass this. However, on chrome 80-81, SameSite=lax  cookies can be sent with post requests if they are less than 2 minutes old.

