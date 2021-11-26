a = 316508952642

b = 54575449882

n = 404993569381



E = EllipticCurve(GF(n), [0, 0, 0, a, b])



base = E ([391109997465, 167359562362])
pub = E ([209038982304, 168517698208])



factors = factor(base.order())
primes = [x[0]**x[1] for x in factors]
print(primes)
dlogs = []
for fac in primes:
    t = int(int(base.order()) / int(fac))
    dlog = discrete_log(t*pub,t*base,operation="+")
    dlogs += [dlog]
    print("factor: "+str(fac)+", Discrete Log: "+str(dlog))
n = crt(dlogs,primes)
print("Private key:", n)
print("Verify:",n * base == pub)
