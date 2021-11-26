# Weak Password

Category: Web

> It seems your login bypass skills are now famous! One of my friends has given you a challenge: figure out his password on this [site](http://weak_password.tjctf.org/). He's told me that his username is admin, and that his password is made of up only lowercase letters. (Wrap the password with tjctf{...})

This is a blind sql injection challenge. We can use the sql `like` query to deduce the password.

Server code:

```python
cursor.execute('SELECT username, password FROM `userandpassword` WHERE username=\'%s\' AND password=\'%s\'' % (username, password))
```

Payload:

```sql
username=admin' and password like 'a%'--
```

The login will succeed if the password starts with 'a'. We can iterate through all the lowercase characters until the login succeeds. We can then repeat the process with the next character:  

```sql
username=admin' and password like 'aa%'--
```

Binary search can also be used, but is not required as the search space is small.
## Flag

`tjctf{blinded}`
