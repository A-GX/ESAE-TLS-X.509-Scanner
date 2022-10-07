import json
from base64 import b64encode
from pprint import pprint

f = open("final-out/ct-by-chain", 'w')
d = open("final-out/ctName-by-chain.sorted", 'r')
dict = {}
dic = d.readlines()
for l in dic :
    l = l.split(':')
    dict[l[0]] = l[-2]
    print(l)


with open('final-out/list-ct-chain', 'r') as fobj:
    data = fobj.readlines()

logs = {}
seen = {}
seen_org = {
    'Google' : False,
    'DigiCert' : False,
    'Cloudflare' : False,
    "Let's Encrypt" : False,
    'Sectigo' : False,
}

org = {
    'Google' : 0,
    'DigiCert' : 0,
    'Cloudflare' : 0,
    "Let's Encrypt" : 0,
    'Sectigo' : 0,
}
tot = 0

for l in data:
    test = bytearray.fromhex(l[3:-2].replace(':', ''))
    test = b64encode(test).decode()
    if l == '[\n' or l == ']\n':
        tot += 0.5
        for k in seen.keys():
            seen[k] = False
        for k in seen_org.keys():
            seen_org[k] = False
    else :
        if not l[3:-2] in seen.keys() or seen[l[3:-2]]==False:
            seen[l[3:-2]] = True
            if not (test in logs.keys()):
                logs[test] = 1
            else :
                logs[test] += 1
            if not seen_org[dict[test]] :
                org[dict[test]] += 1
                seen_org[dict[test]] = True

for i in logs.keys():
    f.write(i + ' ' + str(logs[i]) + ' ' + str(logs[i]/tot) + ' ' + dict[i] + ' ' + str(org[dict[i]]/tot) + '\n')

f.close()