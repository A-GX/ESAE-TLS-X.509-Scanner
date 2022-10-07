import json
from base64 import b64encode
from pprint import pprint

f = open("final-out/ct-by-chain", 'w')

with open('final-out/list-ct-chain', 'r') as fobj:
    data = fobj.readlines()

logs = {}
seen = {}
tot = 0

for l in data:
    test = bytearray.fromhex(l[3:-2].replace(':', ''))
    test = b64encode(test).decode()
    print(test)
    if l == '[\n' or l == ']\n':
        for k in seen.keys():
            seen[k] = False
    else :
        if not l[3:-2] in seen.keys() or seen[l[3:-2]]==False:
            print("ok")
            seen[l[3:-2]] = True
            tot += 1
            if not (test in logs.keys()):
                print("sad")
                logs[test] = 1
            else :
                logs[test] += 1

for i in logs.keys():
    f.write(i + ' ' + str(logs[i]) + ' ' + str(logs[i]/tot) + '\n')

f.close()