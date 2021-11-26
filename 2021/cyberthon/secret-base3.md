# Secret base 3

This challenge is slightly different from the others. Poking further in the `users_table`, we find the password for `proxy`

```
Payload: username = a' union select 'a', password, 'c' from users_table where username not like 'admin' and username not like 'flag';#
Response: Invalid password for Sup3Rsecur3pR0xYPa5Sw0rd! 
```

Going over to the `proxy.php` page in the web app, we can enter a URL and the page will say we are surfing < that URL>. However, if we attempt to surf a `webhook.site` url, no request is received. This is the guessy part. If we enter exactly `http://localhost/camera.php` however, a 3D image is displayed. Navigating around the image, we find a QR code which contains the flag: `Cyberthon{All_Y0ur_B@s3_Are_B3l0ng_T0_uS}`.



