# Circus

Category: Web

> They called me a clown for using PHP, but little did they know I used military-grade SHA256! I'll bet you can't even login to a single account!
>
> Brute force is NOT required
>
> http://circus.tjctf.org/

PHP + hashing reminds me of [magic hashes](https://www.whitehatsec.com/blog/magic-hashes/). I tried a few [SHA256 magic hashes](https://github.com/spaze/hashes/blob/master/sha256.md) on the login page, but it kept saying "invalid credentials". Running dirb on the site provided a major breakthrough:

```shell
▶ dirb https://circus.tjctf.org

---- Scanning URL: https://circus.tjctf.org/ ----
+ https://circus.tjctf.org/.git/HEAD (CODE:500|SIZE:579)
```

The exposed .git directory allows us to access the source code, as well as the history of the project. I used [Git Dumper](https://github.com/arthaud/git-dumper) to download the reconstruct a git repository.

Relevant parts of `index.php`

```php
<?php
$mysqli = new mysqli(NULL, NULL, NULL, "circus");
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$res = $stmt->get_result();
if ($res->num_rows === 0)
{
        $error = "Invalid credentials";
}
else
{
        $row = $res->fetch_assoc();
        if (hash('sha256', $password) == $row["password"])
        {
            // Show flag
        }
}
?>

```

The "Invalid credentials" error was due to the username not being in the database. I then tried using wfuzz to guess valid usernames, but to no avail. I realized that the git repository has not revealed all its secrets.

```
commit 4879af041fba89b387e751a94bfe5dbee4bd7528 (HEAD -> master)
Author: kfb <kfb@circus.tjctf.org>
Date:   Mon Mar 23 09:04:00 2020 -0700

    oops

commit e2731f0ea54feb0a892fd5377a932053bb3baf61
Author: kfb <kfb@circus.tjctf.org>
Date:   Mon Mar 23 09:02:34 2020 -0700

    Initial commit

```

There was another commit before HEAD. 

```
▶ ls
backup.sh  backups  css  img  index.php  js  lib  logout.php
```

Yay a backups folder. The backups folder contained a database dump.

```sql
INSERT INTO `users` VALUES (1,'Forappou1936','0f8669b02353a43e11faa0d7cfd23045d594a1d643010eec222b8d92f1d678a4','Cesar','Penniman'),(2,'Mighte','cd828420a657e5c992cb0d6eefb19083bf352d16c30be33c453672a37d43d317','Patricia','Davis'),(3,'Forianst1945','cc6e171d481acaa87d8d5984f011af38113747efe01440c20e3a714e25ce6632','John','Massey'),(4,'Coughtly','2c8167237444737a09363443f32e04254ecd6308b9c0c4a7df24e6cf566309e5','David','Stalling'),(5,'Stralf','4d4c9fbdb276b6cf05800a7006afb011ab8957fb184f5a3156dd8c01868849f5','Derek','Nadeau'),
....
```

We can now execute our attack! Grepping password hashes starting with `0e` yields a few candidates.

```
(931,'Daysim','0e00947da9a20f712b29a4d09d202561365a3ce0c201374ee5cb2f27ecf4b663','James','Baumann')
(773,'Andon1956','0e75759761935916943951971647195794671357976597614357959761597165','Rosie','Kelly')
(679,'Ancel1950','0e9c2dcd9b5ee48cef19b1f6b51296803ed1b4de65eceb106810068b153c123c','Angel','Barnum')
(628,'Humothisent','0eda68663eb36c99dd5a081bdb936e743555f12ef5dad5ed5bc7adb65e4cc388','Margaret','Moore')
```

But the attack only works on hashes where all the characters after `0e` are numbers because PHP interprets that as 0^<stuff after 0e> = 0. This means `Andon1956` is our lucky account to be hacked! 

```
Username: Andon1956
Password: TyNOQHUS
```

The password hashes to `0e66298694359207596086558843543959518835691168370379069085300385` which also evaluates to 0 in PHP.

Yay we have logged in!

Flag: `tjctf{juggl1n9_cl0wn_up_in_th3_b4ck}`

