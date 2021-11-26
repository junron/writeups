# Zipped up

Category: Misc

> My friend changed the password of his Minecraft account that I was using so that I would stop being so addicted. Now he wants me to work for the password and sent me this [zip file](https://static.tjctf.org/663d7cda5bde67bd38a8de1f07fb9fab9dd8dd0b75607bb459c899acb0ace980_0.zip). I tried unzipping the folder, but it just led to another zipped file. Can you find me the password so I can play Minecraft again?

We are provided with a zip file. Opening it yields yet another archive. Opening all the archives manually will take too long, so I automated it. The script can be found in [script.py](script.py). No dependencies are required.

After running the script, 1001 txt files are generated. 1.txt contains `tjctf{n0t_th3_fl4g}` which is clearly not the flag. I used `grep` to find files that do not contain the string `n0t_th3_fl4g`.

```shell
grep -v n0t_th3_fl4g *
```

Flag: `tjctf{p3sky_z1p_f1L35}`

