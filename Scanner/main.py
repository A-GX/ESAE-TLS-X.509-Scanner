#################################################
#                libraries import               #
#################################################
import sys
from os.path import exists # check if file exists

#################################################
#                Global Variables               #
#################################################
ERR_MISSING_OPTION = "\033[91m[Missing Option]: missing option in front of the file, please see -help\033[0m"
ERR_SHOULD_BE_FILE = "\033[91m[Should Be a File]: the slot after command -{} should be a file name, not another command.\033[0m"
ERR_MISSING_ARG = "\033[91m[Missing Arguments]: You are missing some mandatory arguments, please see -help\033[0m"
LOG_TLS = None
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
            print("Checking if is option")
            #################################################
            #              Option to give file              #
            #################################################
            if arg[1:] == "log-tls":
                i += 1 # next arg = output file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                LOG_TLS = open(f_name, "w") # Need to check if we are allowed to read the file !!
            
            if arg[1:] == "log-x509":
                i += 1 # next arg = output file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                LOG_X509 = open(f_name, "w") # Need to check if we are allowed to read the file !!


            if arg[1:] == "in":
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

            if arg[1:] == "block-list":
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
            
            if arg[1:] == "root-store":
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
    if not (LOG_TLS is None) :
        LOG_TLS.close()
    if not(LOG_X509 is None) :
        LOG_X509.close()
    if not (BLOCK_LIST is None) :
        BLOCK_LIST.close()
    if not (IN is None) :
        IN.close()
    if not(ROOT_STORE is None) :
        ROOT_STORE.close()

def main():
    analyse_options()
    
    if (
        LOG_TLS is None or
        LOG_X509 is None or
        BLOCK_LIST is None or
        IN is None or
        ROOT_STORE is None
    ):
        raise ValueError(ERR_MISSING_ARG)

    close_files()



if __name__ == "__main__":
    main()