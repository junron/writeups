# Secure Flag Distribution Service

> We've recently discovered that APOCALYPSE is running an illegal [flag distribution service](http://aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg:50401/) to share flags among all their agents. Can you infiltrate their system and take a look? Seems like they're using some OTP system to ensure that only their members can login.

The challenge consists of two services, `auth-server` and `otp-server`. However, we can only interact with `auth-server`

Here's an abbreviated version of each.

`auth-server`

```python

@app.post('/request')
async def request_OTP(email: str = Form(...)):
    r = requests.get(f'http://{OTP_SERVER}/sendtoken/{email}')
    result = r.json()['status']

    if result:
        return {'status': True}
    return return {'status': False}

@app.post('/verify')
async def authenticate(token: str = Form(...)):
    r = requests.get(f'http://{OTP_SERVER}/verify/{token}')
    result = r.json()['status']
    if result:
        return {'status': True, message: getenv('FLAG')}
    return return {'status': False}
```

`otp-server`

```python
@app.get('/sendtoken/{email}')
async def send_OTP(email: str):
    if query_email(email):
        if not send_otp(generate_token(email), email):
            return { 'status': False }
    return { 'status': True }

@app.get('/verify/{token}')
async def verify_OTP(token: str):
    if not is_token_valid(token):
        return { 'status': False }
    invalidate_token(token)
    return { 'status': True }
```

This challenge is quite difficult to analyze as there are so many parts and it's not obvious what the vulnerable part is. Let's look at it part by part.

## `send_OTP`

```python
async def send_OTP(email: str):
    if query_email(email):
        if not send_otp(generate_token(email), email):
            return { 'status': False }
    return { 'status': True }
```

There's a lot of useless red herrings here. This function doesn't actually send any emails, nor does it do any validation on the email (at least not as far as I can tell). We can just treat it as a route that always returns `{ 'status': True }`. This will be useful later.

## `verify_OTP`

```python
async def verify_OTP(token: str):
    if not is_token_valid(token):
        return { 'status': False }
    invalidate_token(token)
    return { 'status': True }
```

Again, this function doesn't actually do anything. Maybe it does, but until we can guess a valid OTP, it will always return `{ 'status': False }`. If you've analyzed up to here, you'll probably think this challenge is some kind of web + crypto thingy where OTP is an JWT or flask token. At least that's what I thought during the CTF.

## `request_OTP`

```python
async def request_OTP(email: str = Form(...)):
    r = requests.get(f'http://{OTP_SERVER}/sendtoken/{email}')
    result = r.json()['status']

    if result:
        return {'status': True}
    return return {'status': False}
```

This code reads `email` from the post data and sends it to the OTP server's `send_OTP` function. The vulnerable code is here, but it's so innocent it's easy to miss. 

```python
r = requests.get(f'http://{OTP_SERVER}/sendtoken/{email}')
```

Python's f-strings are really useful for concatenating stuff together. However, when dealing with URLs and paths, we need to be extra careful to deal with [path traversal](https://owasp.org/www-community/attacks/Path_Traversal) attacks. For example, if `email=../`, the effective request URL would be `f'http://{OTP_SERVER}/'` as `..` instructs the web server to load a resource from the parent directory. 

Using this attack, we can actually control the value of `r` by pointing the request URL to something we want. To get the flag, we want something that returns `{'status': True}`, like `send_OTP`. 

Thus the final payload:

```
curl -X POST -d "token=../sendtoken/bleh" http://aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg:50401/verify
```

Flag:

```
Cyberthon{h3y_5h4r1ng_fl4g5_15_4g41n5t_th3_rul35}
```



This challenge is so easy to exploit yet the exploit is so easy to miss. It's not surprising nobody solved it during the CTF.

