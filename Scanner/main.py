#################################################
#                libraries import               #
#################################################
### Public Libraries
#from time import sleep
#from pprint import pprint
import sys
from os import getcwd # testing purposes
from os.path import exists # check if file exists
from ipaddress import ip_address, ip_network # to check if ip in network
import socket # to convert all host name into ip addresses
from threading import Thread
import time
### Project defined
import LOG
import TLS

#################################################
#                Global Variables               #
#################################################
ERR_MISSING_OPTION = "\033[91m[Missing Option]: missing option in front of the file, please see -help\033[0m"
ERR_SHOULD_BE_FILE = "\033[91m[Should Be a File]: the slot after command -{} should be a file name, not another command.\033[0m"
ERR_MISSING_ARG = "\033[91m[Missing Arguments]: You are missing some mandatory arguments, please see -help\033[0m"
LOG_ERR = None
LOG_X509 = None
IN = None
BLOCK_LIST = None
ROOT_STORE = None

def analyse_options():
    """
    ----Function----
    Name :      Analyse_options()
    Args :      None
    Effect :    Analyse option given during the call to the scanner 
                (like -help, -out output.txt, etc...)
    Return:      None
    """
    i = 1
    while i <= len(sys.argv)-1 :
        arg = sys.argv[i]
        if arg[0] == '-':
            #################################################
            #              Option to give file              #
            #################################################
            if arg[1:] == "log-err":
                global LOG_ERR
                i += 1 # next arg = output file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                LOG_ERR = open(f_name, "wb") # Need to check if we are allowed to read the file !!
            
            elif arg[1:] == "log-x509":
                global LOG_X509
                i += 1 # next arg = output file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                LOG_X509 = open(f_name, "w") # Need to check if we are allowed to read the file !!


            elif arg[1:] == "in":
                global IN
                i += 1 # next arg = input file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                ok = False
                while not ok : # don't stop while file not valid
                    try:
                        IN = open(f_name, "r")
                        ok = True
                    except Exception as e:
                        print(e)
                        f_name = input("Correct file name :\n> ")

            elif arg[1:] == "block-list":
                global BLOCK_LIST
                i += 1 # next arg = input file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                ok = False
                while not ok : # don't stop while file not valid
                    try:
                        BLOCK_LIST = open(f_name, "r")
                        ok = True
                    except Exception as e:
                        print(e)
                        f_name = input("Correct file name :\n> ")
            
            elif arg[1:] == "root-store":
                global ROOT_STORE
                i += 1 # next arg = output file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                ok = False
                while not ok : # don't stop while file not valid
                    try:
                        ROOT_STORE = open(f_name, "r")
                        ok = True
                    except Exception as e:
                        print(e)
                        f_name = input("Correct file name :\n> ")
                ROOT_STORE.close() # we want don't want to open the file, just be sur eit is accessible
                ROOT_STORE = f_name # and we save the path to it


            #################################################
            #                 Other options                 #
            #################################################
            if arg[1:] == "help":
                print("help")

        else :
            raise ValueError(ERR_MISSING_OPTION)
        
        i += 1 # increment


def close_files():
    """
    ----Function----
    Name :      close_files()
    Args :      None
    Effect :    close all files opened by the user arguments
                while calling the scanner
    Return:     None
    """
    if not (LOG_ERR is None) :
        LOG_ERR.close()
    if not(LOG_X509 is None) :
        LOG_X509.close()
    if not (BLOCK_LIST is None) :
        BLOCK_LIST.close()
    if not (IN is None) :
        IN.close()

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
        "Domain": [],
        "Network": [],
        "IP": [],
    }
    list_lignes = file.readlines()
    for ligne in list_lignes:
        ligne = ligne[:-1] # we don't want the '\n'
        if inp : # input format give domain + ip, we just do on the ip
            domain = ligne.split(",")[0]
            ligne = ligne.split(",")[1]
        try: # try to get lign as an ip address
            ip_address(ligne)
            result["IP"].append(ligne)
            if inp :
                result["Domain"].append(domain)
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
    Return:     list of (host,ip) to scan not black listed (that we are actually authorised to scan)
    """
    if not(in_list["Network"] == []):
        raise ValueError("TODO: no netword should  be here")
    result = []
    cnt = 0 # count how many ip are in result
    for ip in in_list["IP"]:
        if not ip in b_list["IP"] :
            add = True
            for net in b_list["Network"]:
                if not (ip_address(ip) in ip_network(net)):
                    add = add and True
                else : 
                    add = add and False
            if add:
                result.append((in_list["Domain"][cnt],ip))
                cnt += 1
    return result




def main():
    """
    Testing setup :
        working dir : [.../]TLS-X.509-Scanner/Scanner
        LOG_ERR  : test-out/tls.log
        LOG_X509 : test-out/x509.log
        BLOCK_LIST : test-input-files/week3-blocklist.txt
        IN : test-input-files/week3-input_testing.csv
        ROOT_STORE : root_store/week3-roots.pem

        --> cmd : python3 main.py -log-err test-out/error.log -log-x509 test-out/x509.log \
-block-list test-input-files/week3-blocklist.txt \
-in test-input-files/week3-input_testing.csv -root-store root_store/week3-roots.pem
    """
    st0=time.time()
    analyse_options()
    
    if (
        LOG_ERR is None or
        LOG_X509 is None or
        BLOCK_LIST is None or
        IN is None or
        ROOT_STORE is None
    ):
        close_files()
        raise ValueError(ERR_MISSING_ARG)
    
    b_list =  extract(BLOCK_LIST)
    in_list = extract(IN,True) # "Network" field should be empty
    to_scan = set_to_scan(b_list, in_list)
    # initialise the object to write the logs
    output_logs = LOG.Log(LOG_X509,LOG_ERR)
    connection_threads = []
    st1 = time.time()
    for (dn,ip) in to_scan :
        connection = Thread(target = TLS.tls, args = (2,ip,dn,ROOT_STORE,output_logs))
        connection_threads.append(connection)
        connection.start()  
    for connection in connection_threads :
        connection.join()
    close_files()
    end = time.time()
    print("Total execution time : {} --- Scanning time : {}     <seconds>".format(end-st0, end-st1))


if __name__ == "__main__":
    main()