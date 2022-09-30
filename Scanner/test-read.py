#################################################
#                libraries import               #
#################################################
### Public Libraries
import sys
from os.path import exists # check if file exists
from ipaddress import ip_address, ip_network # to check if ip in network
import socket # to convert all host name into ip addresses
from pprint import pprint
### Project defined
import LOG as LOG

def extract(file, inp = False):
    """
    ----Function----
    Name :      extract()
    Args :      file opened in reading
    Effect :    extract ip, domain and network specified in the file,
                and put it into a dic
    Return:     dic of ip, network and domain
    """
    result = {
        "Network": [],
        "IP": [],
    }
    list_lignes = file.readlines()
    for ligne in list_lignes:
        if inp : # input format give domain + ip, we just do on the ip
            ligne = ligne.split(",")[1]
        ligne = ligne[:-1] # we don't want the '\n'
        try: # try to get lign as an ip address
            ip_address(ligne)
            result["IP"].append(ligne)
        except ValueError: # if it does not work
            if '/' in ligne: # it is either a network
                result["Network"].append(ligne)
            else : # or a domain name
                try:
                    result["IP"].append(socket.gethostbyname(ligne))
                except socket.gaierror as e:
                    print(str(e) + ": " + ligne)
    return result


def set_to_scan(b_list, in_list):
    """
    ----Function----
    Name :      set_to_scan()
    Args :      b_list(dic) -> dictionary of domain / network / ip we don't want to scan
                in_list(dic) -> dictionary fo ip we want to scan
    Effect :    check if ip to scan are blacklisted
    Return:     list of ip to scan not black listed (that we are actually authorised to scan)
    """
    if not(in_list["Network"] == []):
        raise ValueError("TODO: no netword should  be here")
    result = []
    for ip in in_list["IP"]:
        if not ip in b_list["IP"] :
            add = True
            for net in b_list["Network"]:
                if not (ip_address(ip) in ip_network(net)):
                    add = add and True
                else : 
                    add = add and False
            if add:
                result.append(ip)
    return result


if __name__ == "__main__":
   b_list = open("/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/test-input-files/week3-blocklist.txt", "r")
   in_list = open("/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/test-input-files/week3-input_testing.csv","r")
   b = extract(b_list)
   i = extract(in_list, True)
   print(set_to_scan(b,i)[0:9])