## Local file inclusion

**Files of interest:**

- `/etc/passwd`: Probably the first thing to check
- `/proc/self/environ`: Environment variables
- `/proc/self/cmdline`: Get what command the process was run with (can expose absolute path)
- Source code for the program
- `Dockerfile`
- `/etc/hosts`: Is it running in docker?
- `~/.bashrc`, `~/.bash_history`
- `~/.ssh/config`, `~/.ssh/id_rsa`



**PHP Stuff**

- Base64 encode: `php://filter/convert.base64-encode/resource=<file>` (Helpful to read source code of PHP files without executing)
- [expect://](https://www.php.net/manual/en/wrappers.expect.php): Probably won't work, but nice RCE

