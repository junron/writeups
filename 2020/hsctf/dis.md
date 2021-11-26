# Dis

Category: Reversing

Points: 340

> I lost my source code and all I can find is this disassembly.

A [file](disas) containing [python bytecode](https://docs.python.org/3/library/dis.html) is provided.

With some effort, we can decompile the python bytecode. The results are in [vuln.py](vuln.py)

Function e is particularly troublesome because of the nested nature of the functions.

We can then use z3 to solve:

```python
def solveString(expected, function):
    length = len(expected)
    solver = Solver()
    x = [BitVec('x' + str(i), 32) for i in range(length)]
    res = function(x)
    for i in range(length):
        solver.add(res[i] == expected[i])
    if solver.check() == z3.sat:
        model = solver.model()
        return [transform(model.eval(x[i])) for i in range(length)]
    else:
        return "No solution"
    return "".join([chr(c) for c in original])
```

Flag: `flag{5tr4ng3_d1s45s3mbly_1c0a88}`